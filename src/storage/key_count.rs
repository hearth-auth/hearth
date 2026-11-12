//! Exact per-realm key counts for the prefixes in
//! [`COUNTED_KEY_PREFIXES`](crate::core::COUNTED_KEY_PREFIXES) (#644).
//!
//! The engine keeps one counter per counted prefix and realm, under a reserved
//! key. Every write path changes the counter in the same memtable apply as the
//! write itself, inside the WAL critical section:
//!
//! - a put of a counted key that does not exist adds one;
//! - a delete of a counted key that exists subtracts one;
//! - an overwrite, or a delete of an absent key, changes nothing.
//!
//! The change depends on the key set, not on the operation alone. So each
//! apply keeps `counter == number of keys`, also when WAL replay applies a
//! record again whose effect a flushed SST already holds.
//!
//! A write from outside the engine to a reserved counter key is dropped. A
//! Raft snapshot install or a restore that copies every key of a realm
//! therefore cannot overwrite a counter with a value that does not match the
//! keys.

use std::collections::HashMap;
use std::sync::Arc;

use crate::core::{RealmId, COUNTED_KEY_PREFIXES};
use crate::storage::memtable::{Memtable, MemtableValue};
use crate::storage::sst::SstReader;
use crate::storage::wal::{WalEntry, WalOperation};
use crate::storage::StorageError;

/// One key-value write of a batch.
type KeyValue = (Vec<u8>, Vec<u8>);

/// The new count of each counter key that a batch changes.
type CounterWrites = Vec<(Vec<u8>, u64)>;

/// A batch's puts and deletes.
type Batch = (Vec<KeyValue>, Vec<Vec<u8>>);

/// The first bytes of every reserved counter key. No other key starts with
/// `0xFF`: every other key family is printable ASCII.
const COUNTER_KEY_PREFIX: &[u8] = b"\xFFcount:";

/// The reserved key that holds the count of `prefix` in a realm.
pub(crate) fn counter_key(prefix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(COUNTER_KEY_PREFIX.len() + prefix.len());
    key.extend_from_slice(COUNTER_KEY_PREFIX);
    key.extend_from_slice(prefix);
    key
}

/// True when `key` is a reserved counter key, which only the engine writes.
pub(crate) fn is_counter_key(key: &[u8]) -> bool {
    key.starts_with(COUNTER_KEY_PREFIX)
}

/// The counted prefix that `key` falls under, if any.
pub(crate) fn counted_prefix_of(key: &[u8]) -> Option<&'static [u8]> {
    COUNTED_KEY_PREFIXES
        .iter()
        .copied()
        .find(|prefix| key.starts_with(prefix))
}

/// True when `prefix` is one of the counted prefixes.
pub(crate) fn is_counted_prefix(prefix: &[u8]) -> bool {
    COUNTED_KEY_PREFIXES.contains(&prefix)
}

/// Decodes a stored counter. An absent counter is zero.
///
/// # Errors
///
/// [`StorageError::DeserializationFailed`](crate::storage::StorageError) when
/// the stored value is not eight bytes: a damaged counter is reported, never
/// reset.
pub(crate) fn decode_count(stored: Option<&[u8]>) -> Result<u64, StorageError> {
    crate::storage::decode_u64_counter(stored)
}

/// True when the batch writes at least one counted key.
fn touches_counted_keys(puts: &[(Vec<u8>, Vec<u8>)], deletes: &[Vec<u8>]) -> bool {
    puts.iter().any(|(key, _)| counted_prefix_of(key).is_some())
        || deletes.iter().any(|key| counted_prefix_of(key).is_some())
}

/// The current value of `key`: the memtable (active, then the map that a flush
/// writes out), then the SSTs, newest first. Nothing is cached.
///
/// A flush publishes its SST before it drops the map it writes out, so this
/// order never misses a key that moves out of the memtable meanwhile. The
/// caller passes the SST list loaded *after* the memtable lookup can start.
fn current_value(
    memtable: &Memtable,
    ssts: &dyn Fn() -> Arc<Vec<Arc<SstReader>>>,
    realm_id: &RealmId,
    key: &[u8],
) -> Result<Option<Vec<u8>>, StorageError> {
    match memtable.get_entry(realm_id, key) {
        Some(MemtableValue::Data(data)) => return Ok(Some(data)),
        Some(MemtableValue::Tombstone) => return Ok(None),
        None => {}
    }
    for reader in ssts().iter() {
        match reader.get_uncached(realm_id, key)? {
            Some(MemtableValue::Data(data)) => return Ok(Some(data)),
            Some(MemtableValue::Tombstone) => return Ok(None),
            None => {}
        }
    }
    Ok(None)
}

/// The counter writes that keep every count exact after the batch applies
/// `puts` and then `deletes`, or `None` when the batch writes no counted key.
///
/// Each write is `(counter key, new count)`. A count of zero deletes its
/// counter key, so a realm with no key under a prefix keeps no counter.
///
/// The caller MUST hold the lock that orders writes (the WAL critical
/// section, or replay, which runs alone), so no other write changes a counted
/// key or a counter between this lookup and the apply.
fn counter_puts(
    memtable: &Memtable,
    ssts: &dyn Fn() -> Arc<Vec<Arc<SstReader>>>,
    realm_id: &RealmId,
    puts: &[(Vec<u8>, Vec<u8>)],
    deletes: &[Vec<u8>],
) -> Result<Option<CounterWrites>, StorageError> {
    if !touches_counted_keys(puts, deletes) {
        return Ok(None);
    }
    // What this batch already did to a key, so a key that the batch writes
    // twice counts once.
    let mut present: HashMap<&[u8], bool> = HashMap::new();
    let mut deltas: Vec<(&'static [u8], i64)> = Vec::new();
    let mut add = |prefix: &'static [u8], delta: i64| {
        if let Some(entry) = deltas.iter_mut().find(|(p, _)| *p == prefix) {
            entry.1 += delta;
        } else {
            deltas.push((prefix, delta));
        }
    };
    let ops = puts
        .iter()
        .map(|(key, _)| (key.as_slice(), true))
        .chain(deletes.iter().map(|key| (key.as_slice(), false)));
    for (key, exists_after) in ops {
        let Some(prefix) = counted_prefix_of(key) else {
            continue;
        };
        let existed = match present.get(key) {
            Some(existed) => *existed,
            None => current_value(memtable, ssts, realm_id, key)?.is_some(),
        };
        present.insert(key, exists_after);
        match (existed, exists_after) {
            (false, true) => add(prefix, 1),
            (true, false) => add(prefix, -1),
            _ => {}
        }
    }

    let mut writes = Vec::new();
    for (prefix, delta) in deltas {
        if delta == 0 {
            continue;
        }
        let key = counter_key(prefix);
        let old = decode_count(current_value(memtable, ssts, realm_id, &key)?.as_deref())?;
        let new = old.checked_add_signed(delta).unwrap_or_else(|| {
            // The count and the keys disagree. That needs a write behind the
            // engine's back, so report it and keep the count at zero.
            tracing::error!(delta, "a kept key count went below zero; it stays at zero");
            0
        });
        writes.push((key, new));
    }
    Ok(Some(writes))
}

/// Drops the writes to reserved counter keys. Only the engine writes them.
///
/// Returns `None` when nothing is dropped, so the caller keeps its slices.
pub(crate) fn without_counter_keys(
    puts: &[(Vec<u8>, Vec<u8>)],
    deletes: &[Vec<u8>],
) -> Option<Batch> {
    if !puts.iter().any(|(key, _)| is_counter_key(key))
        && !deletes.iter().any(|k| is_counter_key(k))
    {
        return None;
    }
    Some((
        puts.iter()
            .filter(|(key, _)| !is_counter_key(key))
            .cloned()
            .collect(),
        deletes
            .iter()
            .filter(|key| !is_counter_key(key))
            .cloned()
            .collect(),
    ))
}

/// Applies `puts`, then `deletes`, to the memtable in one write-lock hold,
/// with the counter changes that keep every count exact.
///
/// Returns the counter keys it changed, so the caller can drop them from any
/// read cache.
pub(crate) fn apply_counted(
    memtable: &Memtable,
    ssts: &dyn Fn() -> Arc<Vec<Arc<SstReader>>>,
    realm_id: &RealmId,
    puts: &[(Vec<u8>, Vec<u8>)],
    deletes: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, StorageError> {
    let Some(counters) = counter_puts(memtable, ssts, realm_id, puts, deletes)? else {
        memtable.apply_batch(realm_id, puts, deletes)?;
        return Ok(Vec::new());
    };
    let changed: Vec<Vec<u8>> = counters.iter().map(|(key, _)| key.clone()).collect();
    if counters.is_empty() {
        memtable.apply_batch(realm_id, puts, deletes)?;
        return Ok(changed);
    }
    // The batch itself never writes a counter key (the engine drops such
    // writes), so the counter writes cannot conflict with the batch's own.
    let mut all_puts = puts.to_vec();
    let mut all_deletes = deletes.to_vec();
    for (key, count) in counters {
        if count == 0 {
            all_deletes.push(key);
        } else {
            all_puts.push((key, count.to_le_bytes().to_vec()));
        }
    }
    memtable.apply_batch(realm_id, &all_puts, &all_deletes)?;
    Ok(changed)
}

/// Replays one WAL record into the memtable with the count changes, in the
/// record's own order of puts and deletes.
///
/// A record that writes no counted key replays as before.
pub(crate) fn replay_counted(
    memtable: &Memtable,
    ssts: &dyn Fn() -> Arc<Vec<Arc<SstReader>>>,
    entry: &WalEntry,
) -> Result<(), StorageError> {
    let realm_id = &entry.realm_id;
    match entry.operation {
        WalOperation::Put if !is_counter_key(&entry.key) => {
            apply_counted(
                memtable,
                ssts,
                realm_id,
                &[(entry.key.clone(), entry.value.clone())],
                &[],
            )?;
        }
        WalOperation::Delete if !is_counter_key(&entry.key) => {
            apply_counted(
                memtable,
                ssts,
                realm_id,
                &[],
                std::slice::from_ref(&entry.key),
            )?;
        }
        WalOperation::Put | WalOperation::Delete => {}
        WalOperation::Batch => {
            let sub_entries = crate::storage::wal::decode_batch_payload(&entry.value)?;
            if !sub_entries
                .iter()
                .any(|sub| counted_prefix_of(&sub.key).is_some() || is_counter_key(&sub.key))
            {
                return memtable.apply_wal_entry(entry);
            }
            // Keep the encoded order: a run of puts applies together, and a
            // delete ends the run.
            let mut put_run: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            for sub in sub_entries.iter().filter(|sub| !is_counter_key(&sub.key)) {
                match sub.operation {
                    WalOperation::Delete => {
                        if !put_run.is_empty() {
                            apply_counted(memtable, ssts, realm_id, &put_run, &[])?;
                            put_run.clear();
                        }
                        apply_counted(
                            memtable,
                            ssts,
                            realm_id,
                            &[],
                            std::slice::from_ref(&sub.key),
                        )?;
                    }
                    WalOperation::Put => put_run.push((sub.key.clone(), sub.value.clone())),
                    WalOperation::Batch => {
                        return Err(StorageError::DeserializationFailed {
                            reason: "nested batch in WAL replay".to_string(),
                        });
                    }
                }
            }
            if !put_run.is_empty() {
                apply_counted(memtable, ssts, realm_id, &put_run, &[])?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{RealmId, USER_RECORD_KEY_PREFIX};
    use crate::storage::engine::{EmbeddedStorageEngine, StorageConfig};
    use crate::storage::StorageEngine;

    fn open(dir: &std::path::Path) -> EmbeddedStorageEngine {
        EmbeddedStorageEngine::open(StorageConfig::test_config(dir.to_path_buf())).expect("open")
    }

    fn user_key(name: &str) -> Vec<u8> {
        let mut key = USER_RECORD_KEY_PREFIX.to_vec();
        key.extend_from_slice(name.as_bytes());
        key
    }

    /// The counter as stored, read the way any reader reads a key.
    fn stored_count(engine: &EmbeddedStorageEngine, realm: &RealmId) -> u64 {
        let stored = engine
            .get(realm, &counter_key(USER_RECORD_KEY_PREFIX))
            .expect("get counter");
        decode_count(stored.as_deref()).expect("decode counter")
    }

    /// The number of user keys, by a walk of every key.
    fn walked_count(engine: &EmbeddedStorageEngine, realm: &RealmId) -> u64 {
        let end = crate::storage::prefix_scan_end(USER_RECORD_KEY_PREFIX);
        let keys = engine
            .scan_keys(realm, USER_RECORD_KEY_PREFIX, &end)
            .expect("scan keys");
        keys.len() as u64
    }

    #[test]
    fn the_engine_counts_new_keys_and_removed_keys_under_a_counted_prefix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let engine = open(dir.path());
        let realm = RealmId::generate();

        for name in ["a", "b", "c"] {
            engine.put(&realm, &user_key(name), b"v").expect("put");
        }
        engine
            .put(&realm, &user_key("a"), b"v2")
            .expect("overwrite");
        engine.delete(&realm, &user_key("b")).expect("delete");
        engine
            .delete(&realm, &user_key("absent"))
            .expect("delete absent");
        engine
            .put(&realm, b"usr:email:a@example.com", b"x")
            .expect("uncounted put");

        assert_eq!(stored_count(&engine, &realm), 2);
        assert_eq!(walked_count(&engine, &realm), 2);
    }

    #[test]
    fn every_batch_write_path_keeps_the_count() {
        let dir = tempfile::tempdir().expect("tempdir");
        let engine = open(dir.path());
        let realm = RealmId::generate();

        engine
            .put_batch(
                &realm,
                &[
                    (user_key("a"), b"v".to_vec()),
                    (user_key("b"), b"v".to_vec()),
                ],
            )
            .expect("put_batch");
        // One batch creates `c` and `d` and removes `c` and `a`.
        engine
            .write_batch(
                &realm,
                &[
                    (user_key("c"), b"v".to_vec()),
                    (user_key("d"), b"v".to_vec()),
                ],
                &[user_key("c"), user_key("a")],
            )
            .expect("write_batch");
        let handle = engine
            .enqueue_batch(&realm, &[(user_key("e"), b"v".to_vec())])
            .expect("enqueue_batch");
        engine.await_batch_durable(handle).expect("durable");

        assert_eq!(walked_count(&engine, &realm), 3);
        assert_eq!(stored_count(&engine, &realm), 3);
    }

    #[test]
    fn the_count_stays_exact_after_a_restart_that_replays_flushed_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        {
            let engine = open(dir.path());
            for name in ["a", "b", "c"] {
                engine.put(&realm, &user_key(name), b"v").expect("put");
            }
            // The SST now holds a, b and c. The WAL still holds their records,
            // so the reopen below applies them again on top of the SST.
            engine.flush_memtable().expect("flush");
            engine.delete(&realm, &user_key("b")).expect("delete");
            engine.put(&realm, &user_key("d"), b"v").expect("put");
        }
        let engine = open(dir.path());

        assert_eq!(walked_count(&engine, &realm), 3);
        assert_eq!(stored_count(&engine, &realm), 3);
        assert_eq!(
            engine
                .count_prefix(&realm, USER_RECORD_KEY_PREFIX, 0)
                .expect("count"),
            3
        );
    }

    #[test]
    fn count_prefix_reads_the_kept_count_without_a_walk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let engine = open(dir.path());
        let realm = RealmId::generate();
        for name in ["a", "b"] {
            engine.put(&realm, &user_key(name), b"v").expect("put");
        }
        // A key put behind the counter's back: a walk sees it, the count does
        // not. So the count that `count_prefix` returns comes from the counter.
        engine.put_without_count_for_test(&realm, &user_key("hidden"), b"v");

        assert_eq!(walked_count(&engine, &realm), 3);
        assert_eq!(
            engine
                .count_prefix(&realm, USER_RECORD_KEY_PREFIX, 0)
                .expect("count"),
            2
        );
        assert_eq!(
            engine
                .count_prefix(&realm, USER_RECORD_KEY_PREFIX, 1)
                .expect("capped count"),
            1
        );
    }

    #[test]
    fn a_write_from_outside_to_a_counter_key_is_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let engine = open(dir.path());
        let realm = RealmId::generate();
        engine.put(&realm, &user_key("a"), b"v").expect("put");
        let counter = counter_key(USER_RECORD_KEY_PREFIX);

        engine
            .put(&realm, &counter, &99_u64.to_le_bytes())
            .expect("put counter");
        assert_eq!(stored_count(&engine, &realm), 1);
        engine.delete(&realm, &counter).expect("delete counter");
        assert_eq!(stored_count(&engine, &realm), 1);
        engine
            .write_batch(&realm, &[(counter.clone(), vec![7; 8])], &[])
            .expect("write_batch counter");
        assert_eq!(stored_count(&engine, &realm), 1);
    }

    #[test]
    fn a_count_that_reaches_zero_leaves_no_key_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let engine = open(dir.path());
        let realm = RealmId::generate();
        engine.put(&realm, &user_key("a"), b"v").expect("put");
        engine.delete(&realm, &user_key("a")).expect("delete");

        let every_key = engine
            .scan_keys(&realm, b"", &[0xFF; 256])
            .expect("scan every key");
        assert!(every_key.is_empty(), "left behind: {every_key:?}");
        assert_eq!(stored_count(&engine, &realm), 0);
    }

    #[test]
    fn each_realm_has_its_own_count() {
        let dir = tempfile::tempdir().expect("tempdir");
        let engine = open(dir.path());
        let first = RealmId::generate();
        let second = RealmId::generate();
        engine.put(&first, &user_key("a"), b"v").expect("put");
        engine.put(&second, &user_key("a"), b"v").expect("put");
        engine.put(&second, &user_key("b"), b"v").expect("put");

        assert_eq!(stored_count(&engine, &first), 1);
        assert_eq!(stored_count(&engine, &second), 2);
    }

    #[test]
    fn counter_keys_sort_after_every_counted_prefix() {
        for prefix in COUNTED_KEY_PREFIXES {
            assert!(counted_prefix_of(&counter_key(prefix)).is_none());
            assert!(is_counter_key(&counter_key(prefix)));
            assert!(!is_counter_key(prefix));
            assert!(is_counted_prefix(prefix));
        }
    }
}
