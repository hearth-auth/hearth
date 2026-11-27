//! Raft state machine: applies committed log entries to `EmbeddedStorageEngine`.
//!
//! [`HearthStateMachine`] implements [`RaftStateMachine`] from openraft 0.9.
//!
//! ## spawn_blocking contract
//! `StorageEngine` is synchronous (`fn`, not `async fn`).  Every call to the
//! engine from an async context MUST use `tokio::task::spawn_blocking` to
//! avoid blocking the Tokio executor thread pool under load.
//!
//! ## Snapshots
//! A snapshot is a file in `{data_dir}/raft-snapshots/` (`cluster-file-snapshots`):
//! the record stream of [`super::snapshot_stream`] in a sealed file. It is
//! built from one point-in-time storage view, sent and received in chunks,
//! checked whole before an install changes the store, and restored a batch of
//! rows at a time, so neither side holds the store in memory.

use std::io::{BufReader, Read};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use openraft::storage::RaftSnapshotBuilder;
use openraft::storage::RaftStateMachine;
use openraft::{
    EntryPayload, LogId, Snapshot, SnapshotMeta, StorageError, StorageIOError, StoredMembership,
};
use serde::Serialize;
use tokio::task::spawn_blocking;
use tracing::{debug, info, instrument};

use crate::cluster::read_gate::ReadGate;
use crate::cluster::snapshot_file::{remove_file_off_runtime, SnapshotFile};
use crate::cluster::snapshot_store::{Part, SnapshotStore, StoredSnapshot};
use crate::cluster::snapshot_stream::{Record, StreamReader, StreamWriter};
use crate::cluster::types::{HearthLogResponse, HearthNode, HearthRaftConfig, RaftCommand};
use crate::cluster::ReplicatedWriteObserver;
use crate::core::RealmId;
use crate::storage::{EmbeddedStorageEngine, StorageEngine, SEALED_CHUNK_LEN};

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

// ── Current snapshot ──────────────────────────────────────────────────────────

/// The node's current snapshot, shared by the state machine (install, serve)
/// and its snapshot builders (build). The lock is held only to swap or clone
/// the `Arc`, never across an `.await` or during file I/O.
type SnapshotSlot = Arc<std::sync::Mutex<Option<Arc<StoredSnapshot>>>>;

fn snapshot_slot_get(slot: &SnapshotSlot) -> Option<Arc<StoredSnapshot>> {
    slot.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Stores `snap` unless the slot already holds a snapshot that covers more
/// of the log (a build racing an install must not roll the slot back). The
/// snapshot that loses is retired: its file goes when its last sender drops
/// it.
fn snapshot_slot_offer(slot: &SnapshotSlot, snap: Arc<StoredSnapshot>) {
    // Declared before the guard, so a file is unlinked after the lock is
    // released.
    let loser;
    {
        let mut guard = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let newer = guard
            .as_ref()
            .is_none_or(|cur| cur.meta.last_log_id <= snap.meta.last_log_id);
        loser = if newer {
            guard.replace(snap)
        } else {
            Some(snap)
        };
    }
    if let Some(old) = &loser {
        old.retire();
    }
}

/// Opens a stored snapshot to send it (blocking file I/O).
fn open_for_send(
    store: &SnapshotStore,
    snap: &StoredSnapshot,
) -> Result<Snapshot<HearthRaftConfig>, StorageError<u64>> {
    let file = SnapshotFile::open(store.files(), snap.path()).map_err(io_read_err)?;
    Ok(Snapshot {
        meta: snap.meta.clone(),
        snapshot: Box::new(file),
    })
}

fn join_err(e: tokio::task::JoinError) -> StorageError<u64> {
    io_write_err(std::io::Error::other(e.to_string()))
}

// ── HearthSnapshotBuilder ─────────────────────────────────────────────────────

/// Builds a snapshot file from one point-in-time view of the store.
///
/// Returned by [`HearthStateMachine::get_snapshot_builder`], which takes the
/// view: it holds exactly the entries applied up to `last_applied`, however
/// long the build takes and whatever the state machine applies meanwhile
/// (#818). The build streams the view's rows into the file one at a time.
///
/// Realms are enumerated with [`StorageEngine::list_realms`] — the same source
/// [`restore_snapshot_in_place`] uses for its Phase 1 clear (audit 2026-08-28
/// §4.9#3).  An earlier version enumerated an in-memory `known_realms` set that
/// only `apply` ever filled.  That set is never persisted, so a restarted
/// leader built a snapshot omitting every realm on its own disk, and installing
/// it deleted those realms from every follower.
pub struct HearthSnapshotBuilder {
    /// The storage view at `last_applied`, or why it could not be taken.
    view: Result<Arc<dyn StorageEngine>, String>,
    last_applied: Option<LogId<u64>>,
    last_membership: StoredMembership<u64, HearthNode>,
    /// Where the built snapshot is kept, so the node can serve it.
    current: SnapshotSlot,
    store: SnapshotStore,
}

impl RaftSnapshotBuilder<HearthRaftConfig> for HearthSnapshotBuilder {
    #[instrument(skip(self), name = "snapshot_build")]
    async fn build_snapshot(&mut self) -> Result<Snapshot<HearthRaftConfig>, StorageError<u64>> {
        let view = self
            .view
            .clone()
            .map_err(|e| io_read_err(std::io::Error::other(e)))?;
        let meta = SnapshotMeta {
            last_log_id: self.last_applied,
            last_membership: self.last_membership.clone(),
            snapshot_id: format!(
                "snap-{}-{}",
                self.last_applied.as_ref().map_or(0, |id| id.index),
                uuid::Uuid::new_v4()
            ),
        };
        let store = self.store.clone();
        let current = Arc::clone(&self.current);
        let build_meta = meta.clone();
        let (snapshot, realms, rows) = spawn_blocking(move || {
            let (stored, realms, rows) = write_snapshot(view.as_ref(), &store, build_meta)?;
            let snapshot = open_for_send(&store, &stored)?;
            // Keep it: this node serves it to any follower whose next entry
            // the log no longer holds. Returning it to openraft alone kept
            // nothing, so a leader that had purged its log failed "snapshot
            // not found" and its Raft core stopped.
            snapshot_slot_offer(&current, stored);
            Ok::<_, StorageError<u64>>((snapshot, realms, rows))
        })
        .await
        .map_err(join_err)??;

        info!(
            snapshot_id = %meta.snapshot_id,
            realms,
            rows,
            "snapshot built"
        );
        Ok(snapshot)
    }
}

/// Blocking: streams every row of `view` (except the applied-state rows)
/// into a new snapshot file and keeps it. Returns it with its realm and row
/// counts.
fn write_snapshot(
    view: &dyn StorageEngine,
    store: &SnapshotStore,
    meta: SnapshotMeta<u64, HearthNode>,
) -> Result<(Arc<StoredSnapshot>, u64, u64), StorageError<u64>> {
    let part = store.new_part(Part::Build);
    let written = (|| {
        let writer = store.files().create(&part).map_err(io_write_err)?;
        let mut stream = StreamWriter::new(writer, &meta).map_err(io_write_err)?;
        let (mut realms, mut rows) = (0u64, 0u64);
        for realm in view.list_realms().map_err(io_read_err)? {
            let mut started = false;
            let mut failed = None;
            view.visit_entries(&realm, &[], &[0xFF; 256], &mut |key, value| {
                // The applied-state rows are this node's own record, not
                // replicated data: the installing node writes the
                // snapshot's applied state itself.
                if is_state_machine_meta_key(key) {
                    return ControlFlow::Continue(());
                }
                let row = if started {
                    stream.row(key, value)
                } else {
                    started = true;
                    stream
                        .begin_realm(&realm)
                        .and_then(|()| stream.row(key, value))
                };
                match row {
                    Ok(()) => {
                        rows += 1;
                        ControlFlow::Continue(())
                    }
                    Err(e) => {
                        failed = Some(e);
                        ControlFlow::Break(())
                    }
                }
            })
            .map_err(io_read_err)?;
            if let Some(e) = failed {
                return Err(io_write_err(e));
            }
            realms += u64::from(started);
        }
        stream
            .finish()
            .and_then(crate::storage::SealedWriter::finish)
            .map_err(io_write_err)?;
        Ok((realms, rows))
    })();
    match written {
        Ok((realms, rows)) => {
            let stored = store.keep(&part, meta).map_err(io_write_err)?;
            Ok((stored, realms, rows))
        }
        Err(e) => {
            store.discard(&part);
            Err(e)
        }
    }
}

// ── HearthStateMachine ────────────────────────────────────────────────────────

/// Applies committed Raft entries to [`EmbeddedStorageEngine`].
///
/// The state machine keeps no realm registry of its own.  Both snapshot build
/// and snapshot install enumerate realms with [`StorageEngine::list_realms`],
/// so the two paths can never disagree about which realms exist
/// (audit 2026-08-28 §4.9#3).
pub struct HearthStateMachine {
    /// The underlying storage engine.  Shared with the server — never swapped.
    ///
    /// `build_clustered` passes `Arc::clone(&inner)` here; snapshot install
    /// applies data in-place so the server's `inner` handle always reads
    /// current state without any `Arc` swap (HEA-2126).
    engine: Arc<dyn StorageEngine>,
    /// Last applied log id (updated after every `apply` call).
    last_applied: Option<LogId<u64>>,
    /// Last applied membership config.
    last_membership: StoredMembership<u64, HearthNode>,
    /// Most recently built or installed snapshot (kept for `get_current_snapshot`).
    current_snapshot: SnapshotSlot,
    /// The snapshot files of this node.
    store: SnapshotStore,
    /// Slot for the node-local projection observer (audit 2026-08-28 §4.16#5).
    ///
    /// A shared `OnceLock` rather than a direct field because the state
    /// machine is consumed by `Raft::new` before the identity engine — the
    /// observer's implementor — exists. `build_clustered` keeps a clone of
    /// this slot and the server composition root fills it after construction
    /// via [`super::engine::ClusterEngine::set_replicated_write_observer`].
    observer: Arc<OnceLock<Arc<dyn ReplicatedWriteObserver>>>,
    /// The node's read gate, told the applied index after every apply and
    /// install (see [`ReadGate::note_applied`]). `None` in tests that need
    /// no gate.
    read_gate: Option<Arc<ReadGate>>,
}

impl HearthStateMachine {
    /// Create a state machine wrapping an existing storage engine.
    ///
    /// Loads the applied state persisted by earlier applies (see
    /// [`load_applied_state`]) and the newest snapshot file that checks and
    /// is not ahead of it (reading that file whole). Synchronous storage and
    /// file reads — call it from the blocking pool in async code.
    ///
    /// # Errors
    ///
    /// A storage error, a persisted applied-state row that does not decode,
    /// or an error creating or listing the snapshot directory.
    pub fn new(engine: Arc<EmbeddedStorageEngine>) -> Result<Self, StorageError<u64>> {
        Self::with_observer_slot(engine, Arc::new(OnceLock::new()))
    }

    /// Create a state machine with a shared observer slot.
    ///
    /// The slot may be filled at any later point; applies before that are
    /// simply not observed (matching startup, where the projection is built
    /// by a full scan anyway).
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn with_observer_slot(
        engine: Arc<EmbeddedStorageEngine>,
        observer: Arc<OnceLock<Arc<dyn ReplicatedWriteObserver>>>,
    ) -> Result<Self, StorageError<u64>> {
        let store =
            SnapshotStore::open(engine.sealed_files(), engine.data_dir()).map_err(io_read_err)?;
        let engine: Arc<dyn StorageEngine> = engine;
        let (last_applied, last_membership) = load_applied_state(engine.as_ref())?;
        let current = store.recover(last_applied).map_err(io_read_err)?;
        Ok(Self {
            engine,
            last_applied,
            last_membership,
            current_snapshot: Arc::new(std::sync::Mutex::new(current.map(Arc::new))),
            store,
            observer,
            read_gate: None,
        })
    }

    /// Tells `gate` the applied index after every apply and install,
    /// starting with the one loaded from storage.
    #[must_use]
    pub(crate) fn with_read_gate(mut self, gate: Arc<ReadGate>) -> Self {
        if let Some(applied) = self.last_applied {
            gate.note_applied(applied.index);
        }
        self.read_gate = Some(gate);
        self
    }

    /// Tells the read gate the applied index, if both exist.
    fn note_applied(&self) {
        if let (Some(gate), Some(applied)) = (&self.read_gate, self.last_applied) {
            gate.note_applied(applied.index);
        }
    }

    /// Whether this state machine found no persisted applied state when it
    /// was opened (a node that never applied an entry — or one whose data
    /// directory was written by a binary that did not persist it).
    #[must_use]
    pub fn has_no_applied_state(&self) -> bool {
        self.last_applied.is_none()
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
            // Every entry's effect and the applied-state row that records it
            // land in ONE atomic storage batch (H1): after a crash the
            // persisted applied index is exactly the last entry whose effect is
            // durable, and a restart replays only what was never applied.
            let applied_row = encode_row(&entry.log_id)?;
            let response = match &entry.payload {
                EntryPayload::Blank => {
                    self.write_meta_rows(vec![(SM_APPLIED_KEY.to_vec(), applied_row)])
                        .await?;
                    HearthLogResponse::default()
                }

                EntryPayload::Normal(cmd) => {
                    self.apply_command(entry.log_id.index, applied_row, cmd.clone())
                        .await?
                }

                EntryPayload::Membership(membership) => {
                    let stored = StoredMembership::new(Some(entry.log_id), membership.clone());
                    self.write_meta_rows(vec![
                        (SM_APPLIED_KEY.to_vec(), applied_row),
                        (SM_MEMBERSHIP_KEY.to_vec(), encode_row(&stored)?),
                    ])
                    .await?;
                    self.last_membership = stored;
                    debug!(log_id = ?entry.log_id, "membership change applied");
                    HearthLogResponse::default()
                }
            };
            self.last_applied = Some(entry.log_id);

            responses.push(response);
        }
        self.note_applied();

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
        // The view is taken here, between two applies, so it holds exactly
        // the entries up to `last_applied` (#818). Taking it flushes the
        // memtable: blocking I/O.
        let engine = Arc::clone(&self.engine);
        let view = match spawn_blocking(move || engine.read_snapshot()).await {
            Ok(Ok(Some(view))) => Ok(view),
            Ok(Ok(None)) => Err("the storage engine cannot make a point-in-time view".to_string()),
            Ok(Err(e)) => Err(e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        HearthSnapshotBuilder {
            view,
            last_applied: self.last_applied,
            last_membership: self.last_membership.clone(),
            current: Arc::clone(&self.current_snapshot),
            store: self.store.clone(),
        }
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<Box<SnapshotFile>, StorageError<u64>> {
        let store = self.store.clone();
        let file = spawn_blocking(move || {
            SnapshotFile::create(store.files(), &store.new_part(Part::Receive))
        })
        .await
        .map_err(join_err)?
        .map_err(io_write_err)?;
        Ok(Box::new(file))
    }

    #[instrument(skip(self, snapshot), name = "sm_install_snapshot")]
    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, HearthNode>,
        snapshot: Box<SnapshotFile>,
    ) -> Result<(), StorageError<u64>> {
        // openraft's `shutdown` of the transfer read the file whole and
        // checked it (cluster-file-snapshots, design decision 5): a bad
        // transfer failed there and was sent again.
        let (part, summary) = snapshot.take_received().map_err(io_read_err)?;
        // Until it is kept, a file the install fails on is removed: it must
        // not hold the disk until the next start-up.
        let mut unkept = UnkeptFile::new(&self.store, &part);
        if summary.meta != *meta {
            return Err(io_read_err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the received snapshot's META does not match the install request",
            )));
        }

        let engine = Arc::clone(&self.engine);
        let snapshot_id = meta.snapshot_id.clone();
        // The snapshot's applied state, persisted inside the restore (before
        // its completion marker is cleared), so a node that restarts after an
        // install resumes from it instead of replaying from index 0.
        let mut meta_rows = vec![(
            SM_MEMBERSHIP_KEY.to_vec(),
            encode_row(&meta.last_membership)?,
        )];
        if let Some(last) = &meta.last_log_id {
            meta_rows.push((SM_APPLIED_KEY.to_vec(), encode_row(last)?));
        }

        // Apply the snapshot in-place through the live engine — no directory swap,
        // no new EmbeddedStorageEngine open (HEA-2126).
        //
        // `restore_snapshot_in_place` writes a durable marker before Phase 1 and
        // removes it after Phase 2.  A crash between the two phases leaves the
        // marker on disk; the engine refuses to start on next open rather than
        // silently serving mixed data (HEA-2132).
        // No read until a contact after the install (`cluster-consistency`
        // R3): an error below leaves the gate closed.
        if let Some(gate) = &self.read_gate {
            gate.begin_install();
        }
        let files = self.store.files().clone();
        let restore_from = part.clone();
        spawn_blocking(move || {
            let stream = open_stream(&files, &restore_from)?;
            restore_snapshot_in_place(&engine, stream, &snapshot_id, &meta_rows)
        })
        .await
        .map_err(join_err)??;

        // The store holds the snapshot now: keep its file as this node's
        // snapshot, durably, before the install is acknowledged (design
        // decision 7).
        let store = self.store.clone();
        let kept_meta = meta.clone();
        let stored = spawn_blocking(move || store.keep(&part, kept_meta))
            .await
            .map_err(join_err)?
            .map_err(io_write_err)?;
        unkept.kept();

        // The whole key-space was replaced — node-local projections derived
        // from it (revoked-JTI blocklist, …) must be rebuilt from storage
        // (audit 2026-08-28 §4.16#5). The rebuild scans storage, so it runs
        // on the blocking pool like the restore itself.
        if let Some(obs) = self.observer.get() {
            let obs = Arc::clone(obs);
            spawn_blocking(move || obs.on_replicated_reset())
                .await
                .map_err(join_err)?;
        }

        self.last_applied = meta.last_log_id;
        self.last_membership = meta.last_membership.clone();
        self.note_applied();
        if let Some(gate) = &self.read_gate {
            gate.end_install();
        }

        snapshot_slot_offer(&self.current_snapshot, stored);

        info!(
            snapshot_id = %meta.snapshot_id,
            realms = summary.realms,
            rows = summary.rows,
            "snapshot installed"
        );

        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<HearthRaftConfig>>, StorageError<u64>> {
        let Some(snap) = snapshot_slot_get(&self.current_snapshot) else {
            return Ok(None);
        };
        // The `Arc` keeps a retired file on disk until it is open.
        let store = self.store.clone();
        spawn_blocking(move || open_for_send(&store, &snap).map(Some))
            .await
            .map_err(join_err)?
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// A received file the install has not kept yet: removed (off the runtime
/// thread) when dropped before [`UnkeptFile::kept`].
struct UnkeptFile {
    store: SnapshotStore,
    path: Option<PathBuf>,
}

impl UnkeptFile {
    fn new(store: &SnapshotStore, path: &Path) -> Self {
        Self {
            store: store.clone(),
            path: Some(path.to_path_buf()),
        }
    }

    /// The file is the node's snapshot now: keep it.
    fn kept(&mut self) {
        self.path = None;
    }
}

impl Drop for UnkeptFile {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            remove_file_off_runtime(self.store.files().fs(), path);
        }
    }
}

impl HearthStateMachine {
    /// Writes applied-state rows that belong to no data realm (a blank or a
    /// membership entry) in one atomic batch in [`meta_realm`].
    async fn write_meta_rows(
        &self,
        rows: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<(), StorageError<u64>> {
        let engine = Arc::clone(&self.engine);
        spawn_blocking(move || {
            engine
                .write_batch(&meta_realm(), &rows, &[])
                .map_err(to_write_err)
        })
        .await
        .map_err(|e| io_write_err(std::io::Error::other(e.to_string())))?
    }

    /// Apply a single [`RaftCommand`] to the storage engine via `spawn_blocking`.
    ///
    /// Returns the [`HearthLogResponse`] to propagate back to `client_write` callers.
    /// Unconditional commands always return `success: true`; `PutIfAbsent` returns
    /// `success: false` when the key was already present.
    ///
    /// Every command writes its effect, the entry's applied-state row
    /// (`applied_row`, [`SM_APPLIED_KEY`] in the command's realm) and any
    /// counter sidecar it moves in ONE `write_batch` — atomic, so a crash
    /// never leaves an effect without its applied index or the reverse.
    ///
    /// `log_index` is the index of the entry being applied. An entry can still
    /// be applied a second time: a snapshot's data is scanned while the state
    /// machine keeps applying, so it may already hold the effect of entries
    /// after its declared index, which the installing node then applies again.
    /// Commands on a counter use `log_index` to stay exact across that (see
    /// [`increment_once`]).
    async fn apply_command(
        &mut self,
        log_index: u64,
        applied_row: Vec<u8>,
        cmd: RaftCommand,
    ) -> Result<HearthLogResponse, StorageError<u64>> {
        let engine = Arc::clone(&self.engine);

        let (realm, puts, deletes) = match cmd {
            RaftCommand::Put {
                leader_timestamp: _,
                realm,
                key,
                value,
            } => (realm, vec![(key, value)], Vec::new()),
            RaftCommand::Delete {
                leader_timestamp: _,
                realm,
                key,
            } => (realm, Vec::new(), vec![key]),
            RaftCommand::Batch {
                leader_timestamp: _,
                realm,
                entries,
            } => (realm, entries, Vec::new()),
            RaftCommand::WriteBatch {
                leader_timestamp: _,
                realm,
                puts,
                deletes,
            } => (realm, puts, deletes),
            RaftCommand::PutIfAbsent {
                leader_timestamp: _,
                realm,
                key,
                value,
            } => {
                return self
                    .apply_put_if_absent(log_index, applied_row, realm, key, value)
                    .await
            }
            RaftCommand::IncrementU64 {
                leader_timestamp: _,
                realm,
                key,
            } => {
                return self
                    .apply_increment(log_index, applied_row, realm, key)
                    .await
            }
        };

        let (e_realm, e_puts, e_deletes) = (realm.clone(), puts.clone(), deletes.clone());
        spawn_blocking(move || {
            let moved = moved_sidecars(
                engine.as_ref(),
                &e_realm,
                e_puts.iter().map(|(k, _)| k).chain(&e_deletes),
                log_index,
            )?;
            let mut rows = e_puts;
            rows.extend(moved);
            rows.push((SM_APPLIED_KEY.to_vec(), applied_row));
            engine.write_batch(&e_realm, &rows, &e_deletes)
        })
        .await
        .map_err(|e| io_write_err(std::io::Error::other(e.to_string())))?
        .map_err(to_write_err)?;
        if let Some(obs) = self.observer.get() {
            for (key, value) in &puts {
                obs.on_replicated_put(&realm, key, value);
            }
            for key in &deletes {
                obs.on_replicated_delete(&realm, key);
            }
        }
        Ok(HearthLogResponse::default())
    }

    /// Applies [`RaftCommand::PutIfAbsent`].
    ///
    /// State machine entries are applied sequentially and the state machine
    /// is the only writer of replicated keys, so the check and the write
    /// cannot interleave with another entry's.
    async fn apply_put_if_absent(
        &mut self,
        log_index: u64,
        applied_row: Vec<u8>,
        realm: RealmId,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<HearthLogResponse, StorageError<u64>> {
        let engine = Arc::clone(&self.engine);
        let (e_realm, e_key, e_value) = (realm.clone(), key.clone(), value.clone());
        let success = spawn_blocking(move || {
            let absent = engine.get(&e_realm, &e_key)?.is_none();
            let mut rows = Vec::with_capacity(3);
            if absent {
                rows.extend(moved_sidecars(
                    engine.as_ref(),
                    &e_realm,
                    std::iter::once(&e_key),
                    log_index,
                )?);
                rows.push((e_key, e_value));
            }
            rows.push((SM_APPLIED_KEY.to_vec(), applied_row));
            engine.write_batch(&e_realm, &rows, &[])?;
            Ok::<bool, crate::storage::StorageError>(absent)
        })
        .await
        .map_err(|e| io_write_err(std::io::Error::other(e.to_string())))?
        .map_err(to_write_err)?;
        if success {
            if let Some(obs) = self.observer.get() {
                obs.on_replicated_put(&realm, &key, &value);
            }
        }
        Ok(HearthLogResponse {
            success,
            payload: Vec::new(),
        })
    }

    /// Applies [`RaftCommand::IncrementU64`], returning the counter's value
    /// after this entry as the response payload.
    ///
    /// Entries apply one at a time, so the read-modify-write cannot interleave
    /// with another entry's: every node computes the same successor, and no
    /// two proposals ever receive the same value.
    ///
    /// Re-application-safe: see [`increment_once`]. A re-applied entry changes
    /// nothing and is not reported to the observer.
    ///
    /// A counter (or sidecar) row that does not decode is repaired to the
    /// entry's log index (see [`increment_once`]) and the entry succeeds with
    /// that value. The repair is a function of the replicated state and the
    /// entry alone, so every node makes the same one. Refusing the entry
    /// instead left the corrupted row in place and every later increment was
    /// refused too (control propagation stopped); a fatal storage error would
    /// halt this node's state machine and fail again on every restart.
    async fn apply_increment(
        &mut self,
        log_index: u64,
        applied_row: Vec<u8>,
        realm: RealmId,
        key: Vec<u8>,
    ) -> Result<HearthLogResponse, StorageError<u64>> {
        let engine = Arc::clone(&self.engine);
        let (e_realm, e_key) = (realm.clone(), key.clone());
        let outcome = spawn_blocking(move || {
            increment_once(engine.as_ref(), &e_realm, &e_key, log_index, applied_row)
                .map_err(to_write_err)
        })
        .await
        .map_err(|e| io_write_err(std::io::Error::other(e.to_string())))??;
        let value = match outcome {
            Increment::Repaired { value, reason } => {
                tracing::error!(
                    realm = %realm,
                    reason = %reason,
                    repaired_to = value,
                    "a replicated counter did not decode; repaired it to the entry's log index"
                );
                let bytes = value.to_le_bytes();
                if let Some(obs) = self.observer.get() {
                    obs.on_replicated_put(&realm, &key, &bytes);
                }
                bytes
            }
            Increment::Applied(next) => {
                let value = next.to_le_bytes();
                if let Some(obs) = self.observer.get() {
                    obs.on_replicated_put(&realm, &key, &value);
                }
                value
            }
            Increment::Replayed(current) => current.to_le_bytes(),
        };
        Ok(HearthLogResponse {
            success: true,
            payload: value.to_vec(),
        })
    }
}

/// A storage row: `(key, value)`.
type Row = (Vec<u8>, Vec<u8>);

/// The state machine's applied index and membership.
type AppliedState = (Option<LogId<u64>>, StoredMembership<u64, HearthNode>);

/// The applied-state row: the [`LogId`] of the last entry applied. Written in
/// the realm of every data entry, in the same batch as its effect, and in
/// [`meta_realm`] for blank and membership entries and after a snapshot
/// install. On startup the greatest one is the node's applied index.
const SM_APPLIED_KEY: &[u8] = b"\0raft:sm:applied";

/// The last applied membership ([`StoredMembership`]), in [`meta_realm`].
const SM_MEMBERSHIP_KEY: &[u8] = b"\0raft:sm:membership";

/// The realm holding the applied-state rows that belong to no data realm.
fn meta_realm() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

/// Whether `key` is one of the state machine's own applied-state rows — node
/// state, never snapshot data.
fn is_state_machine_meta_key(key: &[u8]) -> bool {
    key == SM_APPLIED_KEY || key == SM_MEMBERSHIP_KEY
}

fn encode_row<T: Serialize>(value: &T) -> Result<Vec<u8>, StorageError<u64>> {
    serde_json::to_vec(value).map_err(|e| io_write_err(std::io::Error::other(e.to_string())))
}

/// Reads the applied state persisted by [`HearthStateMachine::apply`] and
/// snapshot installs: the greatest applied-state row across every realm, and
/// the stored membership. `(None, default)` for a node that never applied an
/// entry.
///
/// The greatest row is exact: each entry's row is written atomically with its
/// effect and entries apply in order, each durable before the next, so every
/// entry at or below it is durable and none above it is.
fn load_applied_state(engine: &dyn StorageEngine) -> Result<AppliedState, StorageError<u64>> {
    let decode = |bytes: &[u8]| -> Result<LogId<u64>, StorageError<u64>> {
        serde_json::from_slice(bytes).map_err(|e| io_read_err(std::io::Error::other(e.to_string())))
    };
    let mut last_applied: Option<LogId<u64>> = None;
    for realm in engine.list_realms().map_err(io_read_err)? {
        if let Some(bytes) = engine.get(&realm, SM_APPLIED_KEY).map_err(io_read_err)? {
            last_applied = last_applied.max(Some(decode(&bytes)?));
        }
    }
    let membership = match engine
        .get(&meta_realm(), SM_MEMBERSHIP_KEY)
        .map_err(io_read_err)?
    {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| io_read_err(std::io::Error::other(e.to_string())))?,
        None => StoredMembership::default(),
    };
    Ok((last_applied, membership))
}

/// Suffix of the row, next to a counter, that records the index of the last
/// log entry that incremented it.
const APPLIED_INDEX_SUFFIX: &[u8] = b"\0raft:applied-index";

/// The row recording the last log index applied to the counter at `key`.
fn applied_index_key(key: &[u8]) -> Vec<u8> {
    let mut marker = Vec::with_capacity(key.len() + APPLIED_INDEX_SUFFIX.len());
    marker.extend_from_slice(key);
    marker.extend_from_slice(APPLIED_INDEX_SUFFIX);
    marker
}

/// Sidecar rows to rewrite for an entry that writes `keys` (M4): any key that
/// is a counter — it has a sidecar — gets its sidecar set to this entry's
/// index, in the same batch as the write.
///
/// A plain write to a counter (an older binary bumped the control epoch with
/// `Put`) otherwise left the sidecar at a LATER increment's index. Applied a
/// second time (after a snapshot install that already held the later
/// increments), the `Put` reset the counter while the sidecar still said the
/// increments after it had run, so they were skipped and the counter went
/// backwards. Moving the sidecar with the write makes the increments after it
/// apply again, and the counter converges on the same value.
fn moved_sidecars<'k>(
    engine: &dyn StorageEngine,
    realm: &RealmId,
    keys: impl Iterator<Item = &'k Vec<u8>>,
    log_index: u64,
) -> Result<Vec<Row>, crate::storage::StorageError> {
    let mut moved = Vec::new();
    for key in keys {
        if key.ends_with(APPLIED_INDEX_SUFFIX) || is_state_machine_meta_key(key) {
            continue;
        }
        let marker = applied_index_key(key);
        if engine.get(realm, &marker)?.is_some() {
            moved.push((marker, log_index.to_le_bytes().to_vec()));
        }
    }
    Ok(moved)
}

/// What [`increment_once`] did.
#[derive(Debug, PartialEq, Eq)]
enum Increment {
    /// The counter moved to this value.
    Applied(u64),
    /// The entry had already been applied; the counter still holds this value.
    Replayed(u64),
    /// The counter or its sidecar row did not decode; both were repaired to
    /// the entry's index, which is the counter's new value.
    Repaired {
        /// The counter's value after the repair (the entry's log index).
        value: u64,
        /// Why the stored rows did not decode.
        reason: String,
    },
}

/// Increments the counter at `key` for the log entry at `log_index`, exactly
/// once however often that entry is applied, and records the entry's
/// applied-state row (`applied_row`) in the same batch.
///
/// The applied index is persisted with every entry (H1), so a restart no
/// longer replays applied entries — but a node installing a snapshot applies
/// again every entry after the snapshot's declared index, and the snapshot's
/// data (scanned while the leader kept applying) may already include them.
/// Every other command converges when applied twice; an increment would count
/// twice. So the counter carries a sidecar row with the index of the last
/// entry that moved it, written in the same atomic batch: an entry at or below
/// that index has already been counted and changes nothing. The sidecar
/// replicates with the counter (snapshots copy every row of the realm), so a
/// snapshot install brings the leader's pair.
fn increment_once(
    engine: &dyn StorageEngine,
    realm: &RealmId,
    key: &[u8],
    log_index: u64,
    applied_row: Vec<u8>,
) -> Result<Increment, crate::storage::StorageError> {
    let marker = applied_index_key(key);
    let applied = (SM_APPLIED_KEY.to_vec(), applied_row);
    let (current, last_index) = match (
        crate::storage::decode_u64_counter(engine.get(realm, key)?.as_deref()),
        crate::storage::decode_u64_counter(engine.get(realm, &marker)?.as_deref()),
    ) {
        (Ok(current), Ok(last_index)) => (current, last_index),
        (Err(e), _) | (_, Err(e)) => {
            // Repair, the same way on every node: the counter and its sidecar
            // become this entry's index. Every value ever handed out is at most
            // the index of the entry that produced it, so the repaired value is
            // above all of them and the counter stays monotone.
            engine.write_batch(
                realm,
                &[
                    (key.to_vec(), log_index.to_le_bytes().to_vec()),
                    (marker, log_index.to_le_bytes().to_vec()),
                    applied,
                ],
                &[],
            )?;
            return Ok(Increment::Repaired {
                value: log_index,
                reason: e.to_string(),
            });
        }
    };
    if last_index >= log_index {
        engine.write_batch(realm, &[applied], &[])?;
        return Ok(Increment::Replayed(current));
    }
    let next = current.saturating_add(1);
    engine.write_batch(
        realm,
        &[
            (key.to_vec(), next.to_le_bytes().to_vec()),
            (marker, log_index.to_le_bytes().to_vec()),
            applied,
        ],
        &[],
    )?;
    Ok(Increment::Applied(next))
}

/// Most rows in one restore write batch (Phase 1 deletes, Phase 2 puts).
const RESTORE_BATCH_ROWS: usize = 4096;
/// Most key and value bytes in one restore write batch.
const RESTORE_BATCH_BYTES: usize = 4 * 1024 * 1024;

/// Opens the snapshot file at `path` and reads its META (blocking).
fn open_stream(
    files: &crate::storage::SealedFiles,
    path: &Path,
) -> Result<StreamReader<impl Read>, StorageError<u64>> {
    let reader = files.open(path).map_err(io_read_err)?;
    StreamReader::new(BufReader::with_capacity(SEALED_CHUNK_LEN, reader)).map_err(to_read_err)
}

/// Deletes every live key of `realm`, a batch of keys at a time.
fn clear_realm(engine: &Arc<dyn StorageEngine>, realm: &RealmId) -> Result<(), StorageError<u64>> {
    let mut start = Vec::new();
    loop {
        let mut keys: Vec<Vec<u8>> = Vec::new();
        let mut bytes = 0;
        engine
            .visit_keys(realm, &start, &[0xFF; 256], &mut |key| {
                bytes += key.len();
                keys.push(key.to_vec());
                if keys.len() >= RESTORE_BATCH_ROWS || bytes >= RESTORE_BATCH_BYTES {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            })
            .map_err(to_write_err)?;
        let Some(last) = keys.last() else {
            return Ok(());
        };
        let full = keys.len() >= RESTORE_BATCH_ROWS || bytes >= RESTORE_BATCH_BYTES;
        // The next batch starts just after the last key of this one.
        start.clone_from(last);
        start.push(0);
        engine
            .write_batch(realm, &[], &keys)
            .map_err(to_write_err)?;
        if !full {
            return Ok(());
        }
    }
}

/// Writes a restore batch of `realm`'s rows and empties it.
fn put_rows(
    engine: &Arc<dyn StorageEngine>,
    realm: Option<&RealmId>,
    rows: &mut Vec<(Vec<u8>, Vec<u8>)>,
    bytes: &mut usize,
) -> Result<(), StorageError<u64>> {
    if let Some(realm) = realm {
        if !rows.is_empty() {
            engine.put_batch(realm, rows).map_err(to_write_err)?;
        }
    }
    rows.clear();
    *bytes = 0;
    Ok(())
}

/// Blocking: apply a Raft snapshot in-place through the live engine.
///
/// Clears every live key for every realm currently present on disk (memtable
/// and SST files), then replays the snapshot's rows via `put_batch`, reading
/// them from `stream` one at a time. Both phases write batches of at most
/// [`RESTORE_BATCH_ROWS`] rows or [`RESTORE_BATCH_BYTES`] bytes, so the
/// restore's memory does not grow with the store.
/// Because this operates on the same `Arc<dyn StorageEngine>` that the server
/// reads through (the `inner` handle from `build_clustered`), all reads via
/// the server's original `Arc` immediately observe the post-snapshot state —
/// no pointer swap required.
///
/// Phase 1 uses [`StorageEngine::list_realms`] to discover on-disk realms
/// rather than an in-memory set the state machine fills as it applies.  This
/// fixes the HEA-2131 regression: such a set is never persisted, so a restarted
/// follower's was always empty and the previous approach left stale keys from
/// realms the leader deleted during the follower's downtime.
///
/// [`HearthSnapshotBuilder`] enumerates from the same call, so build and
/// install always agree on which realms exist (audit 2026-08-28 §4.9#3).
///
/// The process-local `OPEN_DIRS` guard and the OS-level advisory `LOCK` file
/// remain continuous across the install, so the exclusive lock is never
/// released (HEA-2126 bugs 1–3).
///
/// # Crash safety
///
/// An in-place restore is not atomic across a crash mid-restore.  To make a
/// torn restore detectable rather than silently corrupt, this function writes
/// a `SNAPSHOT_RESTORE_IN_PROGRESS` marker file (via
/// [`StorageEngine::begin_snapshot_restore`]) before Phase 1 and removes it
/// after Phase 2 (via [`StorageEngine::complete_snapshot_restore`]).
///
/// If the process is killed between the two phases the marker remains on disk.
/// When [`EmbeddedStorageEngine::open`] finds the marker it returns
/// [`StorageError::TornSnapshotRestore`] and refuses to serve rather than
/// starting up in a mixed-data state.  The operator can recover by deleting
/// the marker file and restarting (the node will re-request the snapshot from
/// the leader via normal Raft catch-up) — unless its log was purged: Phase 1
/// removed its persisted applied state, so startup refuses and the data
/// directory must be wiped (see `docs/guides/disaster-recovery.md`).
///
/// Note: the directory-swap this replaces was also not crash-atomic — the OS
/// advisory lock file was moved with `data_dir` and immediately unlinked,
/// leaving the directory unprotected after any install (HEA-2126 bug 3).
fn restore_snapshot_in_place<R: Read>(
    engine: &Arc<dyn StorageEngine>,
    mut stream: StreamReader<R>,
    snapshot_id: &str,
    meta_rows: &[(Vec<u8>, Vec<u8>)],
) -> Result<(), StorageError<u64>> {
    // Write a durable marker before Phase 1 so a crash between the two phases
    // is detectable at next startup rather than silently serving mixed data
    // (HEA-2132).  The marker is removed after Phase 2 completes.
    engine
        .begin_snapshot_restore(snapshot_id)
        .map_err(to_write_err)?;

    // Phase 1: delete all live keys for every realm currently on disk.
    //
    // `list_realms` enumerates from the live engine (memtable + SST files), so
    // it correctly clears stale data on a restarted follower (HEA-2131).  The
    // snapshot builder enumerates from the same call (audit §4.9#3).
    let on_disk_realms = engine.list_realms().map_err(to_write_err)?;
    for realm_id in &on_disk_realms {
        clear_realm(engine, realm_id)?;
    }

    // Phase 2: replay the snapshot data, then this node's applied state.
    let mut realm: Option<RealmId> = None;
    let mut rows = Vec::new();
    let mut bytes = 0;
    while let Some(record) = stream.next_record().map_err(to_read_err)? {
        match record {
            Record::Realm(next) => {
                put_rows(engine, realm.as_ref(), &mut rows, &mut bytes)?;
                realm = Some(next);
            }
            Record::Row(key, value) => {
                bytes += key.len() + value.len();
                rows.push((key, value));
                if rows.len() >= RESTORE_BATCH_ROWS || bytes >= RESTORE_BATCH_BYTES {
                    put_rows(engine, realm.as_ref(), &mut rows, &mut bytes)?;
                }
            }
        }
    }
    put_rows(engine, realm.as_ref(), &mut rows, &mut bytes)?;
    engine
        .write_batch(&meta_realm(), meta_rows, &[])
        .map_err(to_write_err)?;

    // Remove the marker: the restore completed cleanly.
    engine.complete_snapshot_restore().map_err(to_write_err)?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "state_machine_install_fence.rs"]
mod install_fence_tests;

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

    fn make_write_batch_entry(
        index: u64,
        realm: RealmId,
        puts: Vec<(Vec<u8>, Vec<u8>)>,
        deletes: Vec<Vec<u8>>,
    ) -> Entry<HearthRaftConfig> {
        Entry {
            log_id: make_log_id(index),
            payload: EntryPayload::Normal(RaftCommand::WriteBatch {
                leader_timestamp: 0,
                realm,
                puts,
                deletes,
            }),
        }
    }

    fn open_sm(dir: &std::path::Path) -> HearthStateMachine {
        let config = StorageConfig::dev(dir.to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("open engine");
        HearthStateMachine::new(Arc::new(engine)).expect("state machine")
    }

    /// Sends `snap` to `to` the way openraft does: into the file `to` opens
    /// for receiving, in 4 MiB chunks, then `shutdown` (which checks it).
    #[allow(clippy::unwrap_used)]
    pub(super) async fn transfer(
        to: &mut HearthStateMachine,
        snap: Snapshot<HearthRaftConfig>,
    ) -> Snapshot<HearthRaftConfig> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
        let mut from = snap.snapshot;
        from.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        let mut received = to.begin_receiving_snapshot().await.unwrap();
        let mut buf = Vec::with_capacity(4 << 20);
        loop {
            buf.clear();
            while buf.len() < buf.capacity() {
                if from.read_buf(&mut buf).await.unwrap() == 0 {
                    break;
                }
            }
            if buf.is_empty() {
                break;
            }
            received.write_all(&buf).await.unwrap();
        }
        received.shutdown().await.unwrap();
        Snapshot {
            meta: snap.meta,
            snapshot: received,
        }
    }

    /// Sends `snap` to `to` and installs it there.
    async fn install_received(
        to: &mut HearthStateMachine,
        snap: Snapshot<HearthRaftConfig>,
    ) -> Result<(), openraft::StorageError<u64>> {
        to.install_snapshot(&snap.meta, snap.snapshot).await
    }

    pub(super) async fn install(
        to: &mut HearthStateMachine,
        snap: Snapshot<HearthRaftConfig>,
    ) -> Result<(), openraft::StorageError<u64>> {
        let snap = transfer(to, snap).await;
        to.install_snapshot(&snap.meta, snap.snapshot).await
    }

    /// The bytes of a snapshot file opened to send.
    #[allow(clippy::unwrap_used)]
    pub(super) async fn snapshot_bytes(file: &mut SnapshotFile) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        file.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        let mut out = Vec::new();
        file.read_to_end(&mut out).await.unwrap();
        out
    }

    /// The rows of a snapshot file opened to send, as (realm, key, value).
    #[allow(clippy::unwrap_used)]
    pub(super) async fn snapshot_rows(file: &mut SnapshotFile) -> Vec<(RealmId, Vec<u8>, Vec<u8>)> {
        let bytes = snapshot_bytes(file).await;
        let mut stream = StreamReader::new(&bytes[..]).unwrap();
        let mut realm = None;
        let mut rows = Vec::new();
        while let Some(record) = stream.next_record().unwrap() {
            match record {
                Record::Realm(r) => realm = Some(r),
                Record::Row(k, v) => rows.push((realm.clone().unwrap(), k, v)),
            }
        }
        rows
    }

    // ── Put / Delete / Batch ──────────────────────────────────────────────────

    /// Task 1.7: each apply tells the read gate its applied index, which
    /// completes a contact waiting for the leader's commit index.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn an_apply_completes_a_contact_waiting_for_its_commit_index() {
        let dir = tempdir().unwrap();
        let gate = Arc::new(ReadGate::new(500));
        let mut sm = open_sm(dir.path()).with_read_gate(Arc::clone(&gate));
        let blank = |index: u64| Entry {
            log_id: make_log_id(index),
            payload: EntryPayload::Blank,
        };
        let now = gate.now_ms();
        gate.record_contact_once_applied(now, Some(2));
        sm.apply([blank(1)]).await.unwrap();
        assert!(!gate.allows_at(now), "index 2 is not applied yet");
        sm.apply([blank(2)]).await.unwrap();
        assert!(gate.allows_at(now), "applied: the contact counts");
    }

    /// §4.9#4: a record and the removal of its old index must reach every node
    /// in ONE log entry, or a follower can apply half of them.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn write_batch_command_applies_puts_and_deletes_together() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(dir.path().join("data").as_path());
        let realm = make_realm();

        sm.apply([make_put_entry(
            1,
            realm.clone(),
            b"old".to_vec(),
            b"v".to_vec(),
        )])
        .await
        .unwrap();
        sm.apply([make_write_batch_entry(
            2,
            realm.clone(),
            vec![(b"new".to_vec(), b"v2".to_vec())],
            vec![b"old".to_vec()],
        )])
        .await
        .unwrap();

        assert_eq!(sm.engine.get(&realm, b"new").unwrap(), Some(b"v2".to_vec()));
        assert_eq!(sm.engine.get(&realm, b"old").unwrap(), None);
    }

    /// `IncrementU64` computes the successor at apply time and returns it, so
    /// two proposals of the same increment receive two distinct values.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn increment_command_returns_successive_values() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(dir.path().join("data").as_path());
        let realm = make_realm();
        let incr = |index: u64| Entry {
            log_id: make_log_id(index),
            payload: EntryPayload::Normal(RaftCommand::IncrementU64 {
                leader_timestamp: 0,
                realm: realm.clone(),
                key: b"ctr".to_vec(),
            }),
        };

        let responses = sm.apply([incr(1), incr(2)]).await.unwrap();
        let values: Vec<u64> = responses
            .iter()
            .map(|r| crate::storage::decode_u64_counter(Some(&r.payload)).unwrap())
            .collect();
        assert_eq!(values, vec![1, 2]);
        assert_eq!(
            sm.engine.get(&realm, b"ctr").unwrap(),
            Some(2_u64.to_le_bytes().to_vec())
        );
    }

    /// A counter (or sidecar) row that does not decode is REPAIRED, the same
    /// way on every node (M5): the counter and its sidecar are set to the
    /// entry's log index — every value ever handed out is at most the index of
    /// the entry that produced it, so the repaired value is still greater than
    /// all of them — and the entry succeeds with that value. It used to be
    /// refused, leaving the corrupted row in place so every later increment
    /// (every control-epoch bump) was refused too and control propagation
    /// silently stopped. A fatal storage error would instead halt the state
    /// machine and fail again on every restart.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn an_undecodable_counter_is_repaired_to_the_entry_index() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(dir.path().join("data").as_path());
        let realm = make_realm();
        let incr = |index: u64, key: &[u8]| Entry {
            log_id: make_log_id(index),
            payload: EntryPayload::Normal(RaftCommand::IncrementU64 {
                leader_timestamp: 0,
                realm: realm.clone(),
                key: key.to_vec(),
            }),
        };
        let value = |r: &HearthLogResponse| crate::storage::decode_u64_counter(Some(&r.payload));
        // A corrupted counter, and a good counter with a corrupted sidecar.
        sm.engine.put(&realm, b"ctr", b"bad").unwrap();
        sm.engine.put(&realm, b"ok", &3_u64.to_le_bytes()).unwrap();
        sm.engine
            .put(&realm, &applied_index_key(b"ok"), b"bad")
            .unwrap();

        let responses = sm
            .apply([
                incr(10, b"ctr"),
                incr(11, b"ok"),
                make_put_entry(12, realm.clone(), b"k".to_vec(), b"v".to_vec()),
                incr(13, b"ctr"),
            ])
            .await
            .expect("a corrupted counter must not fail the state machine");
        assert!(responses[0].success, "the corrupted counter is repaired");
        assert_eq!(
            value(&responses[0]).unwrap(),
            10,
            "repaired to the entry's index"
        );
        assert!(responses[1].success, "a corrupted sidecar is repaired too");
        assert_eq!(value(&responses[1]).unwrap(), 11);
        assert_eq!(
            value(&responses[3]).unwrap(),
            11,
            "the repaired counter increments normally afterwards"
        );
        assert_eq!(
            crate::storage::decode_u64_counter(
                sm.engine
                    .get(&realm, &applied_index_key(b"ctr"))
                    .unwrap()
                    .as_deref()
            )
            .unwrap(),
            13
        );
        assert_eq!(
            sm.engine.get(&realm, b"k").unwrap(),
            Some(b"v".to_vec()),
            "later entries still apply"
        );
    }

    /// An entry can be applied twice — a node installing a snapshot re-applies
    /// the entries after its declared index, whose effects the snapshot's data
    /// may already hold (and, before the applied index was persisted, every
    /// restart re-applied the log). Re-applying an `IncrementU64` must not
    /// count it twice, or that node's control epoch would run ahead of every
    /// other node's.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn a_replayed_increment_is_not_counted_twice() {
        let dir = tempdir().unwrap();
        let data = dir.path().join("data");
        let realm = make_realm();
        let incr = |index: u64| Entry {
            log_id: make_log_id(index),
            payload: EntryPayload::Normal(RaftCommand::IncrementU64 {
                leader_timestamp: 0,
                realm: realm.clone(),
                key: b"ctr".to_vec(),
            }),
        };

        let mut sm = open_sm(&data);
        sm.apply([incr(1), incr(2)]).await.unwrap();
        drop(sm);

        // Restart: a fresh state machine over the same data, fed the same
        // committed entries again, then one new entry.
        let mut sm = open_sm(&data);
        sm.apply([incr(1), incr(2)]).await.unwrap();
        let fresh = sm.apply([incr(3)]).await.unwrap();

        assert_eq!(
            crate::storage::decode_u64_counter(Some(&fresh[0].payload)).unwrap(),
            3,
            "the first new increment after a replay returns 3"
        );
        assert_eq!(
            crate::storage::decode_u64_counter(sm.engine.get(&realm, b"ctr").unwrap().as_deref())
                .unwrap(),
            3,
            "three increments were committed; replaying two of them must not add two more"
        );
    }

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

    /// A snapshot install copies every key of a realm, the counter key
    /// included. The installed node's kept user count must match the users
    /// it then holds, whatever it held before (#644).
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn snapshot_install_leaves_an_exact_user_count() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let realm = make_realm();
        let user = |name: &str| {
            let mut key = crate::core::USER_RECORD_KEY_PREFIX.to_vec();
            key.extend_from_slice(name.as_bytes());
            key
        };

        let snapshot = {
            let mut sm_a = open_sm(&dir_a.path().join("data"));
            sm_a.apply([make_batch_entry(
                1,
                realm.clone(),
                vec![
                    (user("a"), b"1".to_vec()),
                    (user("b"), b"1".to_vec()),
                    (user("c"), b"1".to_vec()),
                ],
            )])
            .await
            .unwrap();
            let mut builder = sm_a.get_snapshot_builder().await;
            builder.build_snapshot().await.unwrap()
        };

        let mut sm_b = open_sm(&dir_b.path().join("data"));
        sm_b.apply([make_batch_entry(
            1,
            realm.clone(),
            vec![(user("a"), b"old".to_vec()), (user("z"), b"old".to_vec())],
        )])
        .await
        .unwrap();
        install(&mut sm_b, snapshot).await.unwrap();

        let prefix = crate::core::USER_RECORD_KEY_PREFIX;
        let walked = sm_b
            .engine
            .scan_keys(&realm, prefix, &crate::storage::prefix_scan_end(prefix))
            .unwrap()
            .len() as u64;
        assert_eq!(walked, 3);
        assert_eq!(sm_b.engine.count_prefix(&realm, prefix, 0).unwrap(), 3);
    }

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
        install(&mut sm_b, snapshot).await.unwrap();

        // Snapshot correctness: same realms on disk and same entries for each realm.
        // (The meta realm holds node B's own applied-state rows, not data.)
        let installed_realms: Vec<_> = sm_b
            .engine
            .list_realms()
            .unwrap()
            .into_iter()
            .filter(|r| *r != meta_realm())
            .collect();
        assert_eq!(installed_realms.len(), 1);
        let realm_id = installed_realms[0].clone();

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

        install(&mut sm, snap).await.unwrap();
        assert!(sm.get_current_snapshot().await.unwrap().is_some());
    }

    /// A leader serves lagging followers the snapshot it BUILT, not only one
    /// it installed. The builder returned the snapshot to openraft and kept
    /// nothing, so `get_current_snapshot` answered `None` on every node that
    /// had never installed one — and a leader that had purged its log (as it
    /// does after every snapshot) failed with "snapshot not found" as soon as
    /// a follower needed it, which openraft treats as a fatal storage error:
    /// the leader's Raft core stopped.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn get_current_snapshot_returns_the_snapshot_this_node_built() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(dir.path().join("data").as_path());
        sm.apply([make_put_entry(
            1,
            make_realm(),
            b"k".to_vec(),
            b"v".to_vec(),
        )])
        .await
        .unwrap();

        let built = sm
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap();

        let current = sm
            .get_current_snapshot()
            .await
            .unwrap()
            .expect("the snapshot this node built must be served to followers");
        assert_eq!(current.meta.snapshot_id, built.meta.snapshot_id);
        let (mut current, mut built) = (current.snapshot, built.snapshot);
        assert_eq!(
            snapshot_bytes(&mut current).await,
            snapshot_bytes(&mut built).await
        );
    }

    // ── File-backed snapshots (cluster-file-snapshots) ───────────────────────

    /// Every key of `realm` on `sm`'s engine.
    #[allow(clippy::unwrap_used)]
    fn keys_of(sm: &HearthStateMachine, realm: &RealmId) -> Vec<Vec<u8>> {
        sm.engine
            .scan(realm, &[], &[0xFF; 256])
            .unwrap()
            .into_iter()
            .map(|e| e.key)
            .filter(|k| !is_state_machine_meta_key(k))
            .collect()
    }

    /// #818: the build read the live engine, so entries applied while it ran
    /// reached the snapshot although its META declared an earlier index.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn a_snapshot_holds_the_state_at_its_index_only() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(&dir.path().join("a"));
        let realm = make_realm();
        sm.apply([make_put_entry(
            1,
            realm.clone(),
            b"k1".to_vec(),
            b"v1".to_vec(),
        )])
        .await
        .unwrap();
        let mut builder = sm.get_snapshot_builder().await;
        // Applied after openraft asked for the builder, before it ran.
        sm.apply([make_put_entry(
            2,
            realm.clone(),
            b"k2".to_vec(),
            b"v2".to_vec(),
        )])
        .await
        .unwrap();
        let snap = builder.build_snapshot().await.unwrap();
        assert_eq!(snap.meta.last_log_id, Some(make_log_id(1)));

        let mut sm_b = open_sm(&dir.path().join("b"));
        install(&mut sm_b, snap).await.unwrap();
        assert_eq!(keys_of(&sm_b, &realm), vec![b"k1".to_vec()]);
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn a_snapshot_survives_a_restart() {
        let dir = tempdir().unwrap();
        let data = dir.path().join("data");
        let built = {
            let mut sm = open_sm(&data);
            sm.apply([make_put_entry(
                1,
                make_realm(),
                b"k".to_vec(),
                b"v".to_vec(),
            )])
            .await
            .unwrap();
            let mut built = sm
                .get_snapshot_builder()
                .await
                .build_snapshot()
                .await
                .unwrap();
            snapshot_bytes(&mut built.snapshot).await
        };
        let mut sm = open_sm(&data);
        let mut current = sm
            .get_current_snapshot()
            .await
            .unwrap()
            .expect("the snapshot is served again after a restart");
        assert_eq!(current.meta.last_log_id, Some(make_log_id(1)));
        assert_eq!(snapshot_bytes(&mut current.snapshot).await, built);
        let files: Vec<_> = std::fs::read_dir(data.join(super::super::snapshot_store::DIR_NAME))
            .unwrap()
            .collect();
        assert_eq!(files.len(), 1, "one snapshot file is kept");
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn an_installed_snapshot_survives_a_restart() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(&dir.path().join("a"));
        sm.apply([make_put_entry(
            4,
            make_realm(),
            b"k".to_vec(),
            b"v".to_vec(),
        )])
        .await
        .unwrap();
        let snap = sm
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap();
        let follower = dir.path().join("b");
        {
            let mut sm_b = open_sm(&follower);
            install(&mut sm_b, snap).await.unwrap();
        }
        let mut sm_b = open_sm(&follower);
        let current = sm_b.get_current_snapshot().await.unwrap().unwrap();
        assert_eq!(current.meta.last_log_id, Some(make_log_id(4)));
    }

    fn put_if_absent_entry(index: u64, realm: RealmId, key: &[u8]) -> Entry<HearthRaftConfig> {
        Entry {
            log_id: make_log_id(index),
            payload: EntryPayload::Normal(RaftCommand::PutIfAbsent {
                leader_timestamp: 0,
                realm,
                key: key.to_vec(),
                value: b"claimed".to_vec(),
            }),
        }
    }

    /// S1, "A conditional write after the snapshot point": a follower that
    /// installs the snapshot of index N and then applies entry N+1 answers
    /// as the leader did.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn a_conditional_write_after_the_snapshot_point_answers_alike() {
        let dir = tempdir().unwrap();
        let mut leader = open_sm(&dir.path().join("a"));
        let realm = make_realm();
        leader
            .apply([make_put_entry(
                1,
                realm.clone(),
                b"k".to_vec(),
                b"v".to_vec(),
            )])
            .await
            .unwrap();
        let mut builder = leader.get_snapshot_builder().await;
        let on_leader = leader
            .apply([put_if_absent_entry(2, realm.clone(), b"claim")])
            .await
            .unwrap();
        let snap = builder.build_snapshot().await.unwrap();

        let mut follower = open_sm(&dir.path().join("b"));
        install(&mut follower, snap).await.unwrap();
        let on_follower = follower
            .apply([put_if_absent_entry(2, realm.clone(), b"claim")])
            .await
            .unwrap();
        assert!(on_leader[0].success, "the claim is new on the leader");
        assert_eq!(on_follower[0].success, on_leader[0].success);
    }

    /// S3: no snapshot file holds a store value in plaintext.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn snapshot_files_hold_no_plaintext() {
        const MARKER: &[u8] = b"PLAINTEXT-MARKER-5c1f";
        let dir = tempdir().unwrap();
        let mut sm = open_sm(&dir.path().join("a"));
        let realm = make_realm();
        sm.apply([make_put_entry(
            1,
            realm.clone(),
            b"k".to_vec(),
            MARKER.repeat(64),
        )])
        .await
        .unwrap();
        let snap = sm
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap();
        let mut sm_b = open_sm(&dir.path().join("b"));
        install(&mut sm_b, snap).await.unwrap();

        for node in ["a", "b"] {
            let snaps = dir
                .path()
                .join(node)
                .join(super::super::snapshot_store::DIR_NAME);
            let files: Vec<_> = std::fs::read_dir(&snaps)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            assert_eq!(files.len(), 1, "{node}: one snapshot file");
            let name = files[0].file_name().unwrap().to_string_lossy().into_owned();
            assert!(name.starts_with("snap-"), "{node}: {name}");
            let raw = std::fs::read(&files[0]).unwrap();
            for needle in [MARKER, b"HRSNAP01".as_slice()] {
                assert!(
                    !raw.windows(needle.len()).any(|w| w == needle),
                    "{node}: {} found in {name}",
                    String::from_utf8_lossy(needle)
                );
            }
        }
    }

    /// S4: a changed byte fails the transfer, the store is unchanged, and
    /// the same snapshot sent again installs.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn a_corrupted_transfer_is_refused_and_can_be_sent_again() {
        use tokio::io::AsyncWriteExt;
        let dir = tempdir().unwrap();
        let mut leader = open_sm(&dir.path().join("a"));
        let realm = make_realm();
        leader
            .apply([make_put_entry(
                1,
                realm.clone(),
                b"new".to_vec(),
                vec![3u8; 9000],
            )])
            .await
            .unwrap();
        let mut snap = leader
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap();
        let bytes = snapshot_bytes(&mut snap.snapshot).await;

        let follower_dir = dir.path().join("b");
        let mut follower = open_sm(&follower_dir);
        follower
            .apply([make_put_entry(
                1,
                realm.clone(),
                b"old".to_vec(),
                b"v".to_vec(),
            )])
            .await
            .unwrap();
        let mut corrupt = bytes.clone();
        let mid = corrupt.len() / 2;
        corrupt[mid] ^= 0x40;
        let mut received = follower.begin_receiving_snapshot().await.unwrap();
        received.write_all(&corrupt).await.unwrap();
        assert!(
            received.shutdown().await.is_err(),
            "the changed byte is caught"
        );
        drop(received);
        assert_eq!(keys_of(&follower, &realm), vec![b"old".to_vec()]);
        let snaps = follower_dir.join(super::super::snapshot_store::DIR_NAME);
        assert!(
            crate::cluster::test_fs::eventually(|| std::fs::read_dir(&snaps).unwrap().count() == 0)
                .await,
            "the refused file is removed"
        );

        install(&mut follower, snap).await.unwrap();
        assert_eq!(keys_of(&follower, &realm), vec![b"new".to_vec()]);
    }

    /// A received file the install cannot use is removed, not left to hold
    /// the disk until the next restart.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn a_failed_install_leaves_no_received_file() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(&dir.path().join("a"));
        let realm = make_realm();
        sm.apply([make_put_entry(
            1,
            realm.clone(),
            b"new".to_vec(),
            b"v".to_vec(),
        )])
        .await
        .unwrap();
        let snap = sm
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap();

        let follower = dir.path().join("b");
        let snaps = follower.join(super::super::snapshot_store::DIR_NAME);
        let mut sm_b = open_sm(&follower);
        let snap = transfer(&mut sm_b, snap).await;
        // The checked file changes on disk before the install reads it.
        let recv: Vec<_> = std::fs::read_dir(&snaps)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(recv.len(), 1);
        let mut raw = std::fs::read(&recv[0]).unwrap();
        raw[100] ^= 1;
        std::fs::write(&recv[0], raw).unwrap();

        assert!(install_received(&mut sm_b, snap).await.is_err());
        assert_eq!(keys_of(&sm_b, &realm), Vec::<Vec<u8>>::new());
        assert!(
            crate::cluster::test_fs::eventually(|| std::fs::read_dir(&snaps).unwrap().count() == 0)
                .await,
            "the received file is removed"
        );
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn a_received_snapshot_with_another_meta_changes_nothing() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(&dir.path().join("a"));
        let realm = make_realm();
        sm.apply([make_put_entry(
            1,
            realm.clone(),
            b"new".to_vec(),
            b"v".to_vec(),
        )])
        .await
        .unwrap();
        let snap = sm
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap();

        let mut sm_b = open_sm(&dir.path().join("b"));
        sm_b.apply([make_put_entry(
            1,
            realm.clone(),
            b"old".to_vec(),
            b"v".to_vec(),
        )])
        .await
        .unwrap();
        let snap = transfer(&mut sm_b, snap).await;
        let mut other = snap.meta.clone();
        other.last_log_id = Some(make_log_id(99));
        assert!(sm_b.install_snapshot(&other, snap.snapshot).await.is_err());
        assert_eq!(keys_of(&sm_b, &realm), vec![b"old".to_vec()]);
    }

    /// The restore clears and writes in batches: more rows than one batch
    /// holds, on both sides, still end in exactly the snapshot's rows.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn an_install_across_many_batches_leaves_exactly_the_snapshot() {
        let dir = tempdir().unwrap();
        let realm = make_realm();
        let rows = |prefix: &str, n: usize| -> Vec<(Vec<u8>, Vec<u8>)> {
            (0..n)
                .map(|i| (format!("{prefix}{i:06}").into_bytes(), vec![7u8; 40]))
                .collect()
        };
        let mut sm = open_sm(&dir.path().join("a"));
        let mut expected: Vec<Vec<u8>> = Vec::new();
        for batch in rows("lead:", 3 * RESTORE_BATCH_ROWS + 5).chunks(1000) {
            sm.engine.put_batch(&realm, batch).unwrap();
            expected.extend(batch.iter().map(|(k, _)| k.clone()));
        }
        sm.apply([make_put_entry(
            1,
            realm.clone(),
            b"zz".to_vec(),
            b"v".to_vec(),
        )])
        .await
        .unwrap();
        expected.push(b"zz".to_vec());
        let snap = sm
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap();

        let mut sm_b = open_sm(&dir.path().join("b"));
        for batch in rows("stale:", 2 * RESTORE_BATCH_ROWS + 9).chunks(1000) {
            sm_b.engine.put_batch(&realm, batch).unwrap();
        }
        install(&mut sm_b, snap).await.unwrap();
        assert_eq!(keys_of(&sm_b, &realm), expected);
    }

    // ── HEA-2131 regression pins ──────────────────────────────────────────────

    /// Audit 2026-08-28 §4.9#3: snapshot build and snapshot install must
    /// enumerate realms from the same source.
    ///
    /// Install clears every realm `list_realms()` reports on disk, then replays
    /// only the realms the payload carries.  While build enumerated the
    /// in-memory `known_realms` set, a leader that restarted — the set is never
    /// persisted — built a snapshot that omitted every realm on its own disk.
    /// Installing that snapshot deleted those realms from every follower.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn snapshot_build_includes_realm_this_node_never_applied() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let realm = make_realm();

        // Restarted leader: the realm's data is already on disk, but the freshly
        // constructed state machine has applied nothing, so `known_realms` is empty.
        let config = StorageConfig::dev(dir_a.path().join("data"));
        let leader_engine: Arc<EmbeddedStorageEngine> =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open engine"));
        leader_engine.put(&realm, b"survives", b"restart").unwrap();

        let mut sm_a = HearthStateMachine::new(Arc::clone(&leader_engine)).expect("state machine");

        let mut builder = sm_a.get_snapshot_builder().await;
        let snapshot = builder.build_snapshot().await.unwrap();

        // Follower: install that snapshot and check the realm reached it.
        let mut sm_b = open_sm(dir_b.path().join("data").as_path());
        install(&mut sm_b, snapshot).await.unwrap();

        assert_eq!(
            sm_b.engine.get(&realm, b"survives").unwrap(),
            Some(b"restart".to_vec()),
            "a realm on the leader's disk must reach the follower; a build that \
             enumerates known_realms omits it and install then deletes it everywhere"
        );
    }

    /// Regression pin for HEA-2131 (restart path): a follower that restarts and
    /// then receives a snapshot must clear on-disk data for realms absent from the
    /// snapshot, even though the fresh state machine has applied nothing.
    ///
    /// Before the fix, Phase 1 of `restore_snapshot_in_place` iterated an
    /// in-memory realm set (empty after restart), skipped the delete loop
    /// entirely, and left stale keys permanently on disk.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn snapshot_install_clears_ondisk_realms_absent_from_snapshot() {
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
        // machine, so it has applied nothing.
        let config = StorageConfig::dev(data_dir.clone());
        let inner: Arc<EmbeddedStorageEngine> =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open engine"));
        inner.put(&realm, b"stale", b"stale_val").unwrap();

        let mut sm = HearthStateMachine::new(Arc::clone(&inner)).expect("state machine");
        assert_eq!(
            sm.last_applied, None,
            "precondition: fresh state machine has applied nothing"
        );
        assert_eq!(
            inner.get(&realm, b"stale").unwrap(),
            Some(b"stale_val".to_vec()),
            "precondition: the stale key is on disk before the install"
        );

        install(&mut sm, snap).await.unwrap();

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
    /// the engine, bypassing `apply`, must be cleared when a snapshot that omits
    /// that realm is installed.
    ///
    /// This covers the same root cause as the restart pin above but without a
    /// process restart: `apply` was never called for the stale realm, rather than
    /// the state machine having been freshly constructed.
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
        // directly (not via apply), so this node never saw the stale realm.
        let config = StorageConfig::dev(data_dir.clone());
        let inner: Arc<EmbeddedStorageEngine> =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open engine"));
        inner.put(&realm_stale, b"stale_key", b"stale_val").unwrap();

        let mut sm = HearthStateMachine::new(Arc::clone(&inner)).expect("state machine");
        assert_eq!(
            sm.last_applied, None,
            "precondition: no prior applies on this state machine"
        );

        install(&mut sm, snap).await.unwrap();

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
        let mut sm = HearthStateMachine::new(Arc::clone(&inner)).expect("state machine");
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

        install(&mut sm, snap).await.unwrap();

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

        install(&mut sm, snap).await.unwrap();

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
        let mut file = snap.snapshot;
        assert_eq!(snapshot_rows(&mut file).await.len(), 20);
    }

    // ── Follower revoked-JTI projection (audit 2026-08-28 §4.16#5) ────────────

    /// An `oauth:revjti:` write applied by the state machine must reach the
    /// node-local revoked-JTI projection without a restart.
    ///
    /// On a follower, a sessionless-token revocation arrives only as this raw
    /// storage write. The projection (`revoked_jti_cache`) was populated once
    /// at startup and updated only by the node's own API handlers, so a token
    /// revoked on the leader stayed valid on every follower until that
    /// follower restarted.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    #[allow(clippy::too_many_lines)] // engines + scope + client + token + follower checks
    async fn applied_revjti_put_reaches_follower_projection() {
        use crate::audit::{AuditEngine, EmbeddedAuditEngine};
        use crate::core::{Clock, FakeClock, Timestamp};
        use crate::identity::{
            decode_claims_unverified, ClientCredentialsRequest, CreateRealmRequest,
            CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
            RegisterClientRequest,
        };
        use crate::rbac::RbacEngine as _;

        let dir = tempdir().unwrap();
        let embedded = Arc::new(
            EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().join("data"))).unwrap(),
        );
        let storage: Arc<dyn StorageEngine> = Arc::clone(&embedded) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let mk_identity = || {
            let audit = Arc::new(EmbeddedAuditEngine::new(
                Arc::clone(&storage),
                Arc::clone(&clock) as Arc<dyn Clock>,
            ));
            EmbeddedIdentityEngine::new(
                Arc::clone(&storage),
                Arc::clone(&clock) as Arc<dyn Clock>,
                identity_config.clone(),
                audit as Arc<dyn AuditEngine>,
            )
            .expect("identity engine")
        };

        // The "leader" seeds the shared replicated state and mints a
        // sessionless client-credentials token.
        let leader = mk_identity();
        let realm = leader
            .create_realm(&CreateRealmRequest {
                name: "revjti-cluster-realm".to_string(),
                config: None,
            })
            .expect("create realm");
        let realm_id = realm.id().clone();
        // The scope registry refuses a scope the realm does not define. The
        // registry lives in the shared replicated storage, so any RBAC engine
        // over it can declare `read`.
        crate::rbac::EmbeddedRbacEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .reconcile_scopes(
            &realm_id,
            &[crate::rbac::ScopeSpec {
                name: "read".to_string(),
                permissions: Some(Vec::new()),
            }],
        )
        .expect("declare scope");
        let secret = "revjti-secret-abcdefgh!";
        let client = leader
            .register_client(
                &realm_id,
                &RegisterClientRequest {
                    client_name: "M2M".to_string(),
                    redirect_uris: vec![],
                    client_secret: Some(secret.to_string()),
                    grant_types: vec!["client_credentials".to_string()],
                    require_consent: false,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register client");
        let response = leader
            .client_credentials_token(
                &realm_id,
                &ClientCredentialsRequest {
                    client_id: client.client_id().clone(),
                    client_secret: Some(secret.to_string()),
                    scope: Some("read".to_string()),
                    dpop_jkt: None,
                    client_assertion_type: None,
                    client_assertion: None,
                    resource: None,
                },
            )
            .expect("client credentials token");
        let token = response.access_token().to_string();
        let claims = decode_claims_unverified(&token).expect("decode");
        let jti = claims.jti.clone().expect("sessionless token carries jti");

        // The "follower": a second engine over the same replicated storage,
        // built before the revocation — its startup scan sees no revocation.
        let follower = Arc::new(mk_identity());
        assert!(
            follower.validate_token(&realm_id, &token).is_ok(),
            "sanity: the follower must accept the token before revocation"
        );

        // The leader's revocation reaches the follower as a raw replicated
        // write applied by the state machine — same key and value the revoke
        // handler writes. Observer wiring mirrors `build_clustered` + the
        // server composition root: slot first, observer registered later.
        let observer_slot: Arc<OnceLock<Arc<dyn ReplicatedWriteObserver>>> =
            Arc::new(OnceLock::new());
        let mut sm = HearthStateMachine::with_observer_slot(
            Arc::clone(&embedded),
            Arc::clone(&observer_slot),
        )
        .expect("state machine");
        observer_slot
            .set(Arc::clone(&follower) as Arc<dyn ReplicatedWriteObserver>)
            .ok();
        let revjti_key = crate::identity::keys::encode_revoked_jti(&jti);
        sm.apply([make_put_entry(
            1,
            realm_id.clone(),
            revjti_key,
            claims.exp.to_le_bytes().to_vec(),
        )])
        .await
        .unwrap();

        let after = follower.validate_token(&realm_id, &token);
        assert!(
            after.is_err(),
            "a token revoked via a replicated write must be refused by the follower \
             without a restart (§4.16#5), got: {after:?}"
        );
    }
}

/// H1: a node restarts after its Raft log was purged, because the state
/// machine's applied state is persisted with every applied entry and returned
/// on startup — openraft then replays only what was never applied.
#[cfg(test)]
mod restart_tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::{BTreeMap, BTreeSet};

    use openraft::storage::{RaftLogStorage, StorageHelper};
    use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId, Membership};
    use tempfile::tempdir;

    use super::tests::install;
    use super::*;
    use crate::cluster::log_store::HearthLogStore;
    use crate::storage::{EmbeddedStorageEngine, StorageConfig};

    fn log_id(index: u64) -> LogId<u64> {
        LogId::new(CommittedLeaderId::new(1, 1), index)
    }

    fn put(index: u64, realm: &RealmId, key: &[u8], value: &[u8]) -> Entry<HearthRaftConfig> {
        Entry {
            log_id: log_id(index),
            payload: EntryPayload::Normal(RaftCommand::Put {
                leader_timestamp: 0,
                realm: realm.clone(),
                key: key.to_vec(),
                value: value.to_vec(),
            }),
        }
    }

    fn incr(index: u64, realm: &RealmId, key: &[u8]) -> Entry<HearthRaftConfig> {
        Entry {
            log_id: log_id(index),
            payload: EntryPayload::Normal(RaftCommand::IncrementU64 {
                leader_timestamp: 0,
                realm: realm.clone(),
                key: key.to_vec(),
            }),
        }
    }

    fn membership(index: u64) -> Entry<HearthRaftConfig> {
        let nodes = BTreeMap::from([(
            1_u64,
            HearthNode {
                addr: "node-1".to_string(),
            },
        )]);
        Entry {
            log_id: log_id(index),
            payload: EntryPayload::Membership(Membership::new(
                vec![BTreeSet::from([1_u64])],
                nodes,
            )),
        }
    }

    fn engine(dir: &std::path::Path) -> Arc<EmbeddedStorageEngine> {
        Arc::new(EmbeddedStorageEngine::open(StorageConfig::dev(dir.join("data"))).unwrap())
    }

    /// One node "life": the entries are appended to the log, committed, and
    /// applied; then the log is purged through `purge_to`.
    async fn first_life(
        dir: &std::path::Path,
        entries: Vec<Entry<HearthRaftConfig>>,
        purge_to: Option<u64>,
    ) {
        let mut log = HearthLogStore::open(&dir.join("raft.db")).unwrap();
        log.append_for_test(&entries);
        let last = entries.last().unwrap().log_id;
        log.save_committed(Some(last)).await.unwrap();
        let mut sm = HearthStateMachine::new(engine(dir)).unwrap();
        sm.apply(entries).await.unwrap();
        if let Some(index) = purge_to {
            log.purge(log_id(index)).await.unwrap();
        }
    }

    /// The real startup path: `Raft::new` runs exactly this.
    async fn restart(dir: &std::path::Path) -> (HearthStateMachine, Option<LogId<u64>>) {
        let mut log = HearthLogStore::open(&dir.join("raft.db")).unwrap();
        let mut sm = HearthStateMachine::new(engine(dir)).unwrap();
        let state = StorageHelper::new(&mut log, &mut sm)
            .get_initial_state()
            .await
            .expect("a node must restart after its log was purged");
        (sm, state.committed)
    }

    /// The reviewer's probe: append 0..9, commit 9, purge to 5, restart. It
    /// used to fail with "Failed to get log entries, expected index: [0, 10),
    /// got [Some(6), Some(9))" — openraft replayed from index 0.
    #[tokio::test]
    async fn a_node_restarts_after_its_log_was_purged() {
        let dir = tempdir().unwrap();
        let realm = RealmId::new(uuid::Uuid::new_v4());
        let mut entries = vec![membership(0)];
        for i in 1..10_u64 {
            entries.push(put(i, &realm, format!("k{i}").as_bytes(), b"v"));
        }
        first_life(dir.path(), entries, Some(5)).await;

        let (mut sm, applied) = restart(dir.path()).await;
        assert_eq!(
            applied.map(|l| l.index),
            Some(9),
            "resumes at the committed index"
        );
        let (last, stored_membership) = sm.applied_state().await.unwrap();
        assert_eq!(last, Some(log_id(9)));
        assert_eq!(
            stored_membership.log_id().map(|l| l.index),
            Some(0),
            "the applied membership survives the restart"
        );
        assert_eq!(sm.engine.get(&realm, b"k9").unwrap(), Some(b"v".to_vec()));
    }

    /// M4's probe through the real restart: `Put(7)` on a counter key, then two
    /// increments. A restart used to replay all three (nothing was persisted):
    /// the Put reset the counter to 7 and the sidecar made both increments
    /// "replays" — the counter went backwards from 9 to 7.
    #[tokio::test]
    async fn a_restart_does_not_replay_applied_entries() {
        let dir = tempdir().unwrap();
        let realm = RealmId::new(uuid::Uuid::new_v4());
        first_life(
            dir.path(),
            vec![
                membership(0),
                put(1, &realm, b"epoch", &7_u64.to_le_bytes()),
                incr(2, &realm, b"epoch"),
                incr(3, &realm, b"epoch"),
            ],
            None,
        )
        .await;
        let (sm, applied) = restart(dir.path()).await;
        assert_eq!(applied.map(|l| l.index), Some(3));
        assert_eq!(
            crate::storage::decode_u64_counter(sm.engine.get(&realm, b"epoch").unwrap().as_deref())
                .unwrap(),
            9
        );
    }

    /// M4 without a restart: a node installing a snapshot re-applies the
    /// entries after the snapshot's declared index, and the snapshot's data may
    /// already include them (it is scanned while the state machine keeps
    /// applying). A `Put` on a counter key re-applied there must move the
    /// sidecar with it, or the increments after it read as replays and the
    /// counter goes backwards.
    #[tokio::test]
    async fn a_reapplied_put_on_a_counter_moves_its_sidecar() {
        let dir = tempdir().unwrap();
        let realm = RealmId::new(uuid::Uuid::new_v4());
        let mut sm = HearthStateMachine::new(engine(dir.path())).unwrap();
        let entries = || {
            vec![
                put(1, &realm, b"epoch", &7_u64.to_le_bytes()),
                incr(2, &realm, b"epoch"),
                incr(3, &realm, b"epoch"),
            ]
        };
        sm.apply(entries()).await.unwrap();
        sm.apply(entries()).await.unwrap();
        assert_eq!(
            crate::storage::decode_u64_counter(sm.engine.get(&realm, b"epoch").unwrap().as_deref())
                .unwrap(),
            9,
            "re-applying the same three entries converges on the same counter"
        );
    }

    /// A snapshot install persists the snapshot's applied state, so a node
    /// that restarts right after installing one does not replay from zero.
    #[tokio::test]
    async fn a_snapshot_install_persists_the_applied_state() {
        let leader_dir = tempdir().unwrap();
        let realm = RealmId::new(uuid::Uuid::new_v4());
        let mut leader = HearthStateMachine::new(engine(leader_dir.path())).unwrap();
        leader
            .apply(vec![
                membership(0),
                put(1, &realm, b"k", b"v"),
                put(2, &realm, b"k2", b"v"),
            ])
            .await
            .unwrap();
        let snapshot = leader
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap();
        let mut snapshot = snapshot;
        let rows = super::tests::snapshot_rows(&mut snapshot.snapshot).await;
        assert!(
            rows.iter().all(|(_, k, _)| !is_state_machine_meta_key(k)),
            "the applied-state rows are node-local, not snapshot data"
        );

        let dir = tempdir().unwrap();
        {
            let mut follower = HearthStateMachine::new(engine(dir.path())).unwrap();
            install(&mut follower, snapshot).await.unwrap();
        }
        let mut follower = HearthStateMachine::new(engine(dir.path())).unwrap();
        let (last, stored_membership) = follower.applied_state().await.unwrap();
        assert_eq!(last, Some(log_id(2)));
        assert_eq!(stored_membership.log_id().map(|l| l.index), Some(0));
    }
}
