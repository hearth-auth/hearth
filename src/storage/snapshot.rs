//! A read-only view of the storage engine at one point in time (#643).
//!
//! [`EmbeddedStorageEngine::read_snapshot`](crate::storage::StorageEngine::read_snapshot)
//! flushes the memtable and keeps the SST list of that moment. A backup reads
//! that list while writes continue against the live engine.

use std::ops::ControlFlow;
use std::sync::Arc;

use crate::core::RealmId;
use crate::storage::key_merge::{self, KeyCursor};
use crate::storage::memtable::MemtableValue;
use crate::storage::sst::SstReader;
use crate::storage::{EntryVisitor, ScanEntry, StorageEngine, StorageError};

/// A read-only storage engine over a fixed list of SSTs.
///
/// An SST file is memory-mapped, so its reader stays valid after compaction
/// replaces or removes the file. The snapshot therefore holds the disk space
/// and the memory of those files until it is dropped.
///
/// Reads skip the hot tier and the shared block cache: a backup reads each
/// block once, and cached blocks would only push out the working set of the
/// live engine. Every write fails with [`StorageError::ReadOnlySnapshot`].
pub(crate) struct SnapshotStorage {
    /// The SST readers, newest first, as the engine keeps them.
    readers: Arc<Vec<Arc<SstReader>>>,
}

impl SnapshotStorage {
    /// A snapshot over `readers`, which MUST be ordered newest first.
    pub(crate) fn new(readers: Arc<Vec<Arc<SstReader>>>) -> Self {
        Self { readers }
    }

    /// One uncached cursor per SST over a realm's `[start, end)` window,
    /// newest first.
    fn cursors(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<Box<dyn KeyCursor + '_>>, StorageError> {
        // A reversed window is refused at the boundary, as the engine does
        // (audit §4.9#7).
        if start > end {
            return Err(StorageError::InvalidRange);
        }
        let mut cursors: Vec<Box<dyn KeyCursor + '_>> = Vec::new();
        for reader in self.readers.iter() {
            cursors.push(Box::new(reader.uncached_cursor(realm_id, start, end)?));
        }
        Ok(cursors)
    }
}

impl StorageEngine for SnapshotStorage {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        for reader in self.readers.iter() {
            match reader.get_uncached(realm_id, key)? {
                Some(MemtableValue::Data(data)) => return Ok(Some(data)),
                Some(MemtableValue::Tombstone) => return Ok(None),
                None => {}
            }
        }
        Ok(None)
    }

    fn put(&self, _realm_id: &RealmId, _key: &[u8], _value: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::ReadOnlySnapshot)
    }

    fn delete(&self, _realm_id: &RealmId, _key: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::ReadOnlySnapshot)
    }

    fn accepts_writes(&self) -> bool {
        false
    }

    fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError> {
        let mut entries = Vec::new();
        self.visit_entries(realm_id, start, end, &mut |key, value| {
            entries.push(ScanEntry {
                key: key.to_vec(),
                value: value.to_vec(),
            });
            ControlFlow::Continue(())
        })?;
        Ok(entries)
    }

    fn scan_keys(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut keys = Vec::new();
        self.visit_keys(realm_id, start, end, &mut |key| {
            keys.push(key.to_vec());
            ControlFlow::Continue(())
        })?;
        Ok(keys)
    }

    fn visit_keys(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
    ) -> Result<(), StorageError> {
        let mut cursors = self.cursors(realm_id, start, end)?;
        key_merge::visit_merged(&mut cursors, visit)
    }

    fn visit_entries(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut EntryVisitor<'_>,
    ) -> Result<(), StorageError> {
        let mut cursors = self.cursors(realm_id, start, end)?;
        key_merge::visit_merged_entries(&mut cursors, visit)
    }

    fn write_batch(
        &self,
        _realm_id: &RealmId,
        _puts: &[(Vec<u8>, Vec<u8>)],
        _deletes: &[Vec<u8>],
    ) -> Result<(), StorageError> {
        Err(StorageError::ReadOnlySnapshot)
    }

    fn list_realms(&self) -> Result<Vec<RealmId>, StorageError> {
        let mut realms = std::collections::BTreeSet::new();
        for reader in self.readers.iter() {
            for (key, _) in reader.iter_all()? {
                realms.insert(key.realm_id().clone());
            }
        }
        Ok(realms.into_iter().collect())
    }

    fn begin_snapshot_restore(&self, _snapshot_id: &str) -> Result<(), StorageError> {
        Err(StorageError::ReadOnlySnapshot)
    }

    fn complete_snapshot_restore(&self) -> Result<(), StorageError> {
        Err(StorageError::ReadOnlySnapshot)
    }

    /// A snapshot does not change, so it is its own snapshot.
    fn read_snapshot(&self) -> Result<Option<Arc<dyn StorageEngine>>, StorageError> {
        Ok(Some(Arc::new(Self::new(Arc::clone(&self.readers)))))
    }
}
