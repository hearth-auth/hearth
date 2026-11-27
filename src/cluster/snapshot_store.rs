//! Where a node keeps its Raft snapshots (`cluster-file-snapshots`, design
//! decision 3).
//!
//! All files are in `{data_dir}/raft-snapshots/`, named with local UUIDs only
//! (never the leader's snapshot id):
//!
//! - `build-<uuid>.part`: a snapshot this node is building;
//! - `recv-<uuid>.part`: a snapshot this node is receiving;
//! - `snap-<uuid>.snap`: a finished snapshot, synced before its rename, with
//!   the directory synced after it.
//!
//! The node keeps one `snap-*` file. A file replaced in the slot is unlinked
//! when the last sender drops it; a file still current at shutdown stays for
//! the next start, which keeps the newest one that checks and deletes the rest
//! ([`SnapshotStore::recover`]).

use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use openraft::LogId;
use tracing::{info, warn};

use crate::cluster::snapshot_file::remove_file_off_runtime;
use crate::cluster::snapshot_stream::{self, Meta, StreamReader};
use crate::storage::{SealedFiles, SEALED_CHUNK_LEN};

/// The directory, under the data directory, that holds snapshot files.
pub const DIR_NAME: &str = "raft-snapshots";

const PART_SUFFIX: &str = ".part";
const SNAP_PREFIX: &str = "snap-";
const SNAP_SUFFIX: &str = ".snap";

/// What a `.part` file is for (its name prefix).
#[derive(Clone, Copy, Debug)]
pub(crate) enum Part {
    /// A snapshot this node builds.
    Build,
    /// A snapshot this node receives.
    Receive,
}

/// The snapshot directory of one node.
#[derive(Clone)]
pub(crate) struct SnapshotStore {
    files: SealedFiles,
    dir: PathBuf,
}

/// A finished snapshot file and its META.
pub(crate) struct StoredSnapshot {
    /// The snapshot's metadata (the META record of its stream).
    pub(crate) meta: Meta,
    path: PathBuf,
    store: SnapshotStore,
    /// Set when a newer snapshot replaces this one: the file is unlinked when
    /// the last holder drops it.
    retired: AtomicBool,
}

impl StoredSnapshot {
    /// The file's path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Marks the file for removal once nothing holds it.
    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
    }
}

impl Drop for StoredSnapshot {
    fn drop(&mut self) {
        if self.retired.load(Ordering::Acquire) {
            // One unlink: a sender that opened the file keeps reading it.
            remove_file_off_runtime(self.store.files.fs(), self.path.clone());
        }
    }
}

impl SnapshotStore {
    /// The snapshot directory under `data_dir`, created if missing. The
    /// data directory is synced, so the new directory's entry survives a
    /// power loss (a snapshot kept in it may be all a node with a purged log
    /// has).
    ///
    /// # Errors
    ///
    /// Any error creating the directory or syncing the data directory.
    pub(crate) fn open(files: SealedFiles, data_dir: &Path) -> io::Result<Self> {
        let dir = data_dir.join(DIR_NAME);
        files.fs().create_dir_all(&dir)?;
        files.fs().sync_dir(data_dir)?;
        Ok(Self { files, dir })
    }

    /// The sealed files the snapshots are written with.
    pub(crate) fn files(&self) -> &SealedFiles {
        &self.files
    }

    /// A new, unused path for a `.part` file.
    pub(crate) fn new_part(&self, part: Part) -> PathBuf {
        let prefix = match part {
            Part::Build => "build-",
            Part::Receive => "recv-",
        };
        self.dir
            .join(format!("{prefix}{}{PART_SUFFIX}", uuid::Uuid::new_v4()))
    }

    /// Renames the synced `.part` file at `part` to a new `snap-*` name and
    /// syncs the directory, so the file survives a crash under its new name.
    ///
    /// # Errors
    ///
    /// Any error renaming the file or syncing the directory.
    pub(crate) fn keep(&self, part: &Path, meta: Meta) -> io::Result<Arc<StoredSnapshot>> {
        let path = self.dir.join(format!(
            "{SNAP_PREFIX}{}{SNAP_SUFFIX}",
            uuid::Uuid::new_v4()
        ));
        self.files.fs().rename(part, &path)?;
        self.files.fs().sync_dir(&self.dir)?;
        Ok(Arc::new(self.stored(meta, path)))
    }

    fn stored(&self, meta: Meta, path: PathBuf) -> StoredSnapshot {
        StoredSnapshot {
            meta,
            path,
            store: self.clone(),
            retired: AtomicBool::new(false),
        }
    }

    /// Removes the file at `path`, logging a failure other than "not found".
    pub(crate) fn discard(&self, path: &Path) {
        match self.files.fs().remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => warn!(path = %path.display(), error = %e, "could not remove a snapshot file"),
        }
    }

    /// At start-up: removes every `.part` file, keeps the newest `snap-*` file
    /// that checks whole and whose META is at or below `applied`, and removes
    /// the rest (design decision 3).
    ///
    /// A snapshot ahead of the applied state is never kept: openraft would
    /// take the state machine to hold it.
    ///
    /// # Errors
    ///
    /// Any error listing the directory. A file that does not check is
    /// removed with a warning, not reported.
    pub(crate) fn recover(
        &self,
        applied: Option<LogId<u64>>,
    ) -> io::Result<Option<StoredSnapshot>> {
        let mut candidates = Vec::new();
        for path in self.files.fs().read_dir(&self.dir)? {
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.ends_with(PART_SUFFIX) {
                info!(file = name, "removing an unfinished snapshot file");
                self.discard(&path);
            } else if name.starts_with(SNAP_PREFIX) && name.ends_with(SNAP_SUFFIX) {
                match self.read_meta(&path) {
                    Ok(meta) if meta.last_log_id <= applied => candidates.push((meta, path)),
                    Ok(_) => {
                        info!(
                            file = name,
                            "removing a snapshot ahead of the applied state"
                        );
                        self.discard(&path);
                    }
                    Err(e) => {
                        warn!(file = name, error = %e, "removing a snapshot file that does not check");
                        self.discard(&path);
                    }
                }
            }
        }
        // Newest first; the first that checks whole is kept.
        candidates.sort_by_key(|c| std::cmp::Reverse(c.0.last_log_id));
        let mut kept = None;
        for (meta, path) in candidates {
            if kept.is_some() {
                self.discard(&path);
                continue;
            }
            match self.verify(&path) {
                Ok(summary) if summary.meta == meta => kept = Some(self.stored(meta, path)),
                Ok(_) => {
                    warn!(path = %path.display(), "removing a snapshot file whose META changed");
                    self.discard(&path);
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "removing a snapshot file that does not check");
                    self.discard(&path);
                }
            }
        }
        Ok(kept)
    }

    /// Reads the META of the snapshot file at `path`.
    fn read_meta(&self, path: &Path) -> io::Result<Meta> {
        let reader = self.files.open(path).map_err(io::Error::other)?;
        Ok(
            StreamReader::new(BufReader::with_capacity(SEALED_CHUNK_LEN, reader))?
                .meta()
                .clone(),
        )
    }

    /// Reads the whole snapshot file at `path` and checks it.
    pub(crate) fn verify(&self, path: &Path) -> io::Result<snapshot_stream::Summary> {
        let reader = self.files.open(path).map_err(io::Error::other)?;
        snapshot_stream::verify(BufReader::with_capacity(SEALED_CHUNK_LEN, reader))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cluster::snapshot_stream::StreamWriter;
    use crate::cluster::test_fs::{eventually, TestFs};
    use crate::storage::Fs;
    use openraft::{CommittedLeaderId, SnapshotMeta, StoredMembership};
    use std::io::Write as _;

    fn log_id(index: u64) -> LogId<u64> {
        LogId::new(CommittedLeaderId::new(1, 1), index)
    }

    fn meta(index: u64) -> Meta {
        SnapshotMeta {
            last_log_id: Some(log_id(index)),
            last_membership: StoredMembership::default(),
            snapshot_id: format!("snap-{index}"),
        }
    }

    fn store(dir: &Path) -> SnapshotStore {
        SnapshotStore::open(SealedFiles::for_tests(dir), dir).unwrap()
    }

    /// Writes a finished snapshot for `index` and keeps it.
    fn write_snap(store: &SnapshotStore, index: u64) -> Arc<StoredSnapshot> {
        let part = store.new_part(Part::Build);
        let writer = store.files().create(&part).unwrap();
        let stream = StreamWriter::new(writer, &meta(index)).unwrap();
        stream.finish().unwrap().finish().unwrap();
        store.keep(&part, meta(index)).unwrap()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(dir.join(DIR_NAME))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        out.sort();
        out
    }

    #[test]
    fn a_kept_snapshot_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let kept = write_snap(&s, 10);
        drop(kept); // not retired: shutdown keeps it
        let again = store(dir.path())
            .recover(Some(log_id(10)))
            .unwrap()
            .unwrap();
        assert_eq!(again.meta, meta(10));
    }

    #[test]
    fn recovery_keeps_the_newest_good_snapshot_at_or_below_applied() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        for i in [5, 10, 20] {
            drop(write_snap(&s, i));
        }
        // A leftover part file and a corrupt newer snapshot.
        std::fs::write(s.new_part(Part::Receive), b"partial").unwrap();
        let bad = write_snap(&s, 15);
        let bad_path = bad.path().to_path_buf();
        drop(bad);
        let mut raw = std::fs::read(&bad_path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        std::fs::write(&bad_path, raw).unwrap();

        // Applied at 17: 20 is ahead, 15 is corrupt, 10 is kept.
        let kept = s.recover(Some(log_id(17))).unwrap().unwrap();
        assert_eq!(kept.meta, meta(10));
        let left = names(dir.path());
        assert_eq!(left.len(), 1, "one snapshot file stays: {left:?}");
        assert!(left[0].starts_with(SNAP_PREFIX) && left[0].ends_with(SNAP_SUFFIX));
        assert_eq!(dir.path().join(DIR_NAME).join(&left[0]), kept.path());
    }

    #[test]
    fn recovery_with_no_applied_state_keeps_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        drop(write_snap(&s, 3));
        assert!(s.recover(None).unwrap().is_none());
        assert_eq!(names(dir.path()), Vec::<String>::new());
    }

    #[test]
    fn a_retired_snapshot_is_removed_when_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let snap = write_snap(&s, 1);
        let path = snap.path().to_path_buf();
        let holder = Arc::clone(&snap);
        snap.retire();
        drop(snap);
        assert!(path.exists(), "a holder keeps the file");
        drop(holder);
        assert!(!path.exists(), "the last holder's drop removes it");
    }

    /// Power loss after the first start must not lose the directory: its
    /// entry in the data directory is synced.
    #[test]
    fn opening_the_store_syncs_its_directory_into_the_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let fs = TestFs::new();
        let files = SealedFiles::for_tests_with(dir.path(), Arc::clone(&fs) as Arc<dyn Fs>);
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        SnapshotStore::open(files, &data).unwrap();
        assert!(
            fs.synced_dirs.lock().unwrap().contains(&data),
            "the data directory is synced after creating {DIR_NAME}/"
        );
    }

    /// Unlinking a large file is blocking I/O: the last holder's drop on a
    /// runtime thread hands the removal to the blocking pool.
    #[tokio::test(flavor = "current_thread")]
    async fn a_retired_snapshot_is_removed_off_the_runtime_thread() {
        let dir = tempfile::tempdir().unwrap();
        let fs = TestFs::new();
        let files = SealedFiles::for_tests_with(dir.path(), Arc::clone(&fs) as Arc<dyn Fs>);
        let s = SnapshotStore::open(files, dir.path()).unwrap();
        let snap = write_snap(&s, 1);
        let path = snap.path().to_path_buf();
        snap.retire();
        drop(snap);
        assert!(eventually(|| !path.exists()).await, "the file is removed");
        let me = std::thread::current().id();
        let removers = fs.removers_of(&path);
        assert_ne!(removers.len(), 0, "the file was removed through the fs");
        assert!(
            removers.iter().all(|t| *t != me),
            "removed on the runtime thread"
        );
    }

    #[test]
    fn a_file_without_a_snapshot_stream_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let path = dir.path().join(DIR_NAME).join("snap-x.snap");
        let mut w = s.files().create(&path).unwrap();
        w.write_all(b"not a snapshot stream").unwrap();
        w.finish().unwrap();
        assert!(s.recover(Some(log_id(100))).unwrap().is_none());
        assert_eq!(names(dir.path()), Vec::<String>::new());
    }
}
