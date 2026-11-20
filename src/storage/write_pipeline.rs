//! Writes of many independent records that share WAL fsyncs (#896).
//!
//! A backup restore writes millions of records, each one its own small
//! atomic batch. One by one, each record waits for its own fsync: on a cloud
//! disk that is about 175–300 records/s, and 10M role assignments take 10–16
//! hours. A [`WritePipeline`] enqueues the batches of many records with
//! [`StorageEngine::enqueue_batch`] before it waits for them, so one
//! group-commit fsync covers many records. Each record is still one atomic WAL
//! record with its own result.

use super::{StorageDurabilityHandle, StorageEngine, StorageError};
use crate::core::RealmId;

/// Most records a pipeline enqueues before it waits for their fsync.
///
/// One fsync covers every record of the pipeline, so the depth sets the
/// records per fsync: at 64, a restore still spent most of its time in
/// fsyncs (12,000 records/s locally); at 512, about 50,000. An enqueue can
/// make the writing thread the group-commit leader, and the other writers wait
/// for it until it waits too (#536): staging 512 records takes about 10 ms,
/// which bounds that wait.
pub(crate) const WRITE_PIPELINE_DEPTH: usize = 512;

/// One record of a pipeline: its result, or its write that is not yet
/// known to be durable.
enum Slot<T, E> {
    Done(Result<T, E>),
    Pending(StorageDurabilityHandle, T),
}

impl<T, E> Slot<T, E> {
    fn leads_commit(&self) -> bool {
        matches!(self, Slot::Pending(handle, _) if handle.leads_commit())
    }
}

/// Writes the records of one realm, each as one atomic batch, and returns one
/// result per record, in order.
///
/// A record's result is `Ok` only once its write is durable. The writer calls
/// [`settle`](Self::settle) before anything that can itself wait for a commit
/// (a durable write, or a lock whose holder may be waiting for one): this
/// thread can lead the group commit, and no other write commits until it
/// waits. Dropping a pipeline settles it too.
pub(crate) struct WritePipeline<'s, T, E> {
    storage: &'s dyn StorageEngine,
    realm_id: &'s RealmId,
    map_err: fn(StorageError) -> E,
    /// The records since the last settle, in order.
    slots: Vec<Slot<T, E>>,
    /// Records of `slots` whose write is not yet known to be durable.
    pending: usize,
    /// The results of the records before `slots`, in order.
    results: Vec<Result<T, E>>,
}

impl<'s, T, E> WritePipeline<'s, T, E> {
    /// A pipeline that writes into `realm_id` of `storage` and reports a
    /// storage error as `map_err` makes it.
    pub(crate) fn new(
        storage: &'s dyn StorageEngine,
        realm_id: &'s RealmId,
        map_err: fn(StorageError) -> E,
    ) -> Self {
        Self {
            storage,
            realm_id,
            map_err,
            slots: Vec::new(),
            pending: 0,
            results: Vec::new(),
        }
    }

    /// Adds the result of a record that writes nothing: skipped or refused.
    pub(crate) fn push_result(&mut self, result: Result<T, E>) {
        if self.slots.is_empty() {
            self.results.push(result);
        } else {
            self.slots.push(Slot::Done(result));
        }
    }

    /// Enqueues the rows of one record as one atomic batch. Its result is
    /// `value` once the batch is durable.
    pub(crate) fn push_rows(&mut self, rows: &[(Vec<u8>, Vec<u8>)], value: T) {
        match self.storage.enqueue_batch(self.realm_id, rows) {
            Ok(handle) => self.push_pending(handle, value),
            Err(e) => self.push_result(Err((self.map_err)(e))),
        }
    }

    /// Enqueues `key` = `value` when `key` is absent. The record's result is
    /// `written` once that write is durable, or `present` when `key` was
    /// already there and nothing was written.
    pub(crate) fn push_if_absent(&mut self, key: &[u8], value: &[u8], written: T, present: T) {
        match self
            .storage
            .enqueue_batch_if_absent(self.realm_id, key, value, &[])
        {
            Ok(Some(handle)) => self.push_pending(handle, written),
            Ok(None) => self.push_result(Ok(present)),
            Err(e) => self.push_result(Err((self.map_err)(e))),
        }
    }

    fn push_pending(&mut self, handle: StorageDurabilityHandle, value: T) {
        self.slots.push(Slot::Pending(handle, value));
        self.pending += 1;
    }

    /// Whether [`WRITE_PIPELINE_DEPTH`] records wait for their fsync: the
    /// writer then settles before it adds more.
    pub(crate) fn is_full(&self) -> bool {
        self.pending >= WRITE_PIPELINE_DEPTH
    }

    /// Waits until every enqueued record is durable.
    ///
    /// The record whose enqueue made this thread the group-commit leader is
    /// awaited first: its wait commits the others. A leader steps down after
    /// a number of batches, and this thread can lead from a later record
    /// while an earlier one is still queued; a wait for that earlier record
    /// first would never end, and every other write would wait too (#536).
    pub(crate) fn settle(&mut self) {
        let slots = std::mem::take(&mut self.slots);
        self.pending = 0;
        let leader = slots.iter().position(Slot::leads_commit);
        let mut slots: Vec<Option<Slot<T, E>>> = slots.into_iter().map(Some).collect();
        let mut settled: Vec<Option<Result<T, E>>> = Vec::with_capacity(slots.len());
        settled.resize_with(slots.len(), || None);
        if let Some(i) = leader {
            if let (Some(slot), Some(out)) =
                (slots.get_mut(i).and_then(Option::take), settled.get_mut(i))
            {
                *out = Some(self.wait(slot));
            }
        }
        for (slot, out) in slots.into_iter().zip(settled.iter_mut()) {
            if let Some(slot) = slot {
                *out = Some(self.wait(slot));
            }
        }
        self.results.extend(settled.into_iter().flatten());
    }

    fn wait(&self, slot: Slot<T, E>) -> Result<T, E> {
        match slot {
            Slot::Done(result) => result,
            Slot::Pending(handle, value) => self
                .storage
                .await_batch_durable(handle)
                .map(|()| value)
                .map_err(self.map_err),
        }
    }

    /// Settles the pipeline and returns one result per record, in order.
    pub(crate) fn finish(mut self) -> Vec<Result<T, E>> {
        self.settle();
        std::mem::take(&mut self.results)
    }
}

impl<T, E> Drop for WritePipeline<'_, T, E> {
    /// A pipeline dropped with records still queued (a panic in its writer)
    /// waits for them: this thread may lead the group commit, and no other
    /// write commits until it waits.
    fn drop(&mut self) {
        if self.pending > 0 {
            self.settle();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::wal::SyncMode;
    use crate::storage::{EmbeddedStorageEngine, StorageConfig};

    fn durable_store() -> (tempfile::TempDir, EmbeddedStorageEngine) {
        let dir = tempfile::tempdir().expect("tmp");
        let mut config = StorageConfig::dev(dir.path().to_path_buf());
        config.wal_config.sync_mode = SyncMode::EveryWrite;
        let store = EmbeddedStorageEngine::open(config).expect("storage");
        (dir, store)
    }

    fn row(i: u32) -> (Vec<u8>, Vec<u8>) {
        (format!("k{i:05}").into_bytes(), i.to_le_bytes().to_vec())
    }

    /// Many records share each fsync, every record is stored, and the
    /// results come back in record order.
    #[test]
    fn records_share_fsyncs_and_keep_their_order() {
        let (_dir, store) = durable_store();
        let realm = RealmId::generate();
        let before = store.wal_sync_count();
        let mut pipeline: WritePipeline<'_, u32, StorageError> =
            WritePipeline::new(&store, &realm, |e| e);
        for i in 0..300 {
            if i % 10 == 3 {
                pipeline.push_result(Ok(i));
            } else {
                pipeline.push_rows(&[row(i)], i);
            }
            if pipeline.is_full() {
                pipeline.settle();
            }
        }
        let results = pipeline.finish();

        let order: Vec<u32> = results.into_iter().map(|r| r.expect("ok")).collect();
        assert_eq!(order, (0..300).collect::<Vec<_>>());
        for i in (0..300).filter(|i| i % 10 != 3) {
            let (key, value) = row(i);
            assert_eq!(store.get(&realm, &key).expect("get"), Some(value));
        }
        let syncs = store.wal_sync_count() - before;
        assert!(syncs <= 30, "{syncs} fsyncs for 270 records");
    }

    /// A key that is already there is not written again, and its record
    /// gets the `present` result.
    #[test]
    fn if_absent_writes_only_an_absent_key() {
        let (_dir, store) = durable_store();
        let realm = RealmId::generate();
        store.put(&realm, b"taken", b"old").expect("put");
        let mut pipeline: WritePipeline<'_, &str, StorageError> =
            WritePipeline::new(&store, &realm, |e| e);
        pipeline.push_if_absent(b"taken", b"new", "written", "present");
        pipeline.push_if_absent(b"free", b"new", "written", "present");
        pipeline.push_if_absent(b"free", b"newer", "written", "present");
        let results: Vec<&str> = pipeline
            .finish()
            .into_iter()
            .map(|r| r.expect("ok"))
            .collect();

        assert_eq!(results, ["present", "written", "present"]);
        assert_eq!(
            store.get(&realm, b"taken").expect("get"),
            Some(b"old".to_vec())
        );
        assert_eq!(
            store.get(&realm, b"free").expect("get"),
            Some(b"new".to_vec())
        );
    }

    /// A pipeline dropped without `finish` still waits for its records, so
    /// the next write of the store is not stuck behind them.
    #[test]
    fn a_dropped_pipeline_waits_for_its_records() {
        let (_dir, store) = durable_store();
        let realm = RealmId::generate();
        {
            let mut pipeline: WritePipeline<'_, u32, StorageError> =
                WritePipeline::new(&store, &realm, |e| e);
            for i in 0..10 {
                pipeline.push_rows(&[row(i)], i);
            }
        }
        store
            .put(&realm, b"after", b"1")
            .expect("a later write commits");
        let (key, value) = row(9);
        assert_eq!(store.get(&realm, &key).expect("get"), Some(value));
    }
}
