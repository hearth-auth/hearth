//! Prefix counting and offset paging on top of [`StorageEngine::visit_keys`].
//!
//! The `StorageEngine` defaults for `count_prefix` and `scan_prefix_paged`
//! delegate here. Both walk the keys under the prefix one at a time and keep
//! none of them, so a count costs memory for one key and a page costs memory
//! for the page: `GET /admin/users` used to collect every user key in the
//! realm to report `total` — about 100 MB per page at 1,000,000 users (#447).

use std::ops::ControlFlow;

use crate::core::RealmId;
use crate::storage::{prefix_scan_end, ScanEntry, StorageEngine, StorageError};

/// The `visit_keys` default for engines without a streaming key walk:
/// collects the range with `scan_keys`, then visits it. Memory grows with the
/// range; [`crate::storage::EmbeddedStorageEngine`] overrides it.
pub(super) fn visit_collected_keys<E: StorageEngine + ?Sized>(
    engine: &E,
    realm_id: &RealmId,
    start: &[u8],
    end: &[u8],
    visit: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
) -> Result<(), StorageError> {
    for key in engine.scan_keys(realm_id, start, end)? {
        if visit(&key).is_break() {
            break;
        }
    }
    Ok(())
}

/// The `count_prefix` default: walks the prefix and counts, stopping at a
/// non-zero `cap`.
pub(super) fn count_prefix<E: StorageEngine + ?Sized>(
    engine: &E,
    realm_id: &RealmId,
    prefix: &[u8],
    cap: u64,
) -> Result<u64, StorageError> {
    if prefix.is_empty() {
        return Ok(0);
    }
    let end = prefix_scan_end(prefix);
    let mut n: u64 = 0;
    engine.visit_keys(realm_id, prefix, &end, &mut |_| {
        n += 1;
        if cap != 0 && n >= cap {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })?;
    Ok(if cap == 0 { n } else { n.min(cap) })
}

/// The `scan_prefix_paged` default.
///
/// One key walk counts the prefix and remembers only two keys: the one at
/// `offset` (the page's first) and the one at `offset + limit` (the first
/// after the page). A value scan then reads exactly that window. The walk
/// stops early only when a non-zero `cap` is reached and the window is known.
pub(super) fn scan_prefix_paged<E: StorageEngine + ?Sized>(
    engine: &E,
    realm_id: &RealmId,
    prefix: &[u8],
    offset: u64,
    limit: u32,
    cap: u64,
) -> Result<(Vec<ScanEntry>, u64), StorageError> {
    if prefix.is_empty() {
        return Ok((Vec::new(), 0));
    }
    let prefix_end = prefix_scan_end(prefix);
    let after_window = offset.saturating_add(u64::from(limit));

    let mut n: u64 = 0;
    let mut window_start: Option<Vec<u8>> = None;
    let mut window_end: Option<Vec<u8>> = None;
    engine.visit_keys(realm_id, prefix, &prefix_end, &mut |key| {
        if n == offset {
            if limit > 0 {
                window_start = Some(key.to_vec());
            }
        } else if n == after_window {
            window_end = Some(key.to_vec());
        }
        n += 1;
        let window_known = limit == 0 || window_end.is_some();
        if window_known && cap != 0 && n >= cap {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })?;
    let total = if cap == 0 { n } else { n.min(cap) };

    let Some(window_start) = window_start else {
        return Ok((Vec::new(), total));
    };
    let window_end = window_end.as_deref().unwrap_or(&prefix_end);
    let mut window = engine.scan(realm_id, &window_start, window_end)?;
    // Keys written inside the window after the walk would lengthen it.
    window.truncate(limit as usize);
    Ok((window, total))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ops::ControlFlow;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::core::RealmId;
    use crate::storage::{ScanEntry, StorageEngine, StorageError};

    /// A read-only store that walks keys only through `visit_keys`. It panics
    /// if anything collects every key in a range (`scan_keys`), and records
    /// the largest value scan it served and how many keys were walked.
    struct WalkOnlyStore {
        rows: BTreeMap<Vec<u8>, Vec<u8>>,
        largest_scan: AtomicUsize,
        scans: AtomicUsize,
        keys_walked: AtomicUsize,
    }

    impl WalkOnlyStore {
        fn with_keys(n: u32) -> Self {
            let rows = (0..n)
                .map(|i| (format!("usr:{i:08}").into_bytes(), i.to_le_bytes().to_vec()))
                // A neighbouring prefix that no `usr:` page may count.
                .chain((0..10).map(|i| (format!("usx:{i}").into_bytes(), Vec::new())))
                .collect();
            Self {
                rows,
                largest_scan: AtomicUsize::new(0),
                scans: AtomicUsize::new(0),
                keys_walked: AtomicUsize::new(0),
            }
        }
    }

    impl StorageEngine for WalkOnlyStore {
        fn get(&self, _realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.rows.get(key).cloned())
        }

        fn put(&self, _: &RealmId, _: &[u8], _: &[u8]) -> Result<(), StorageError> {
            unreachable!("read-only fixture")
        }

        fn delete(&self, _: &RealmId, _: &[u8]) -> Result<(), StorageError> {
            unreachable!("read-only fixture")
        }

        fn scan(
            &self,
            _realm_id: &RealmId,
            start: &[u8],
            end: &[u8],
        ) -> Result<Vec<ScanEntry>, StorageError> {
            let window: Vec<ScanEntry> = self
                .rows
                .range(start.to_vec()..end.to_vec())
                .map(|(key, value)| ScanEntry {
                    key: key.clone(),
                    value: value.clone(),
                })
                .collect();
            self.scans.fetch_add(1, Ordering::SeqCst);
            self.largest_scan.fetch_max(window.len(), Ordering::SeqCst);
            Ok(window)
        }

        fn scan_keys(&self, _: &RealmId, _: &[u8], _: &[u8]) -> Result<Vec<Vec<u8>>, StorageError> {
            panic!("collected every key in the range instead of walking them")
        }

        fn visit_keys(
            &self,
            _realm_id: &RealmId,
            start: &[u8],
            end: &[u8],
            visit: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
        ) -> Result<(), StorageError> {
            for key in self
                .rows
                .range(start.to_vec()..end.to_vec())
                .map(|(k, _)| k)
            {
                self.keys_walked.fetch_add(1, Ordering::SeqCst);
                if visit(key).is_break() {
                    break;
                }
            }
            Ok(())
        }

        fn list_realms(&self) -> Result<Vec<RealmId>, StorageError> {
            Ok(Vec::new())
        }

        fn begin_snapshot_restore(&self, _: &str) -> Result<(), StorageError> {
            Ok(())
        }

        fn complete_snapshot_restore(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    fn key(i: u32) -> Vec<u8> {
        format!("usr:{i:08}").into_bytes()
    }

    fn keys(window: &[ScanEntry]) -> Vec<Vec<u8>> {
        window.iter().map(|e| e.key.clone()).collect()
    }

    // #447: a 200-row page over 100,000 keys collected all 100,000 to count them.
    #[test]
    fn a_page_counts_the_total_without_collecting_the_keys() {
        let store = WalkOnlyStore::with_keys(100_000);
        let realm = RealmId::generate();

        let (window, total) = store
            .scan_prefix_paged(&realm, b"usr:", 0, 200, 0)
            .expect("page");

        assert_eq!(total, 100_000, "cap 0 reports the exact total");
        assert_eq!(keys(&window), (0..200).map(key).collect::<Vec<_>>());
        assert_eq!(
            store.largest_scan.load(Ordering::SeqCst),
            200,
            "the value scan reads the page, not the prefix"
        );
    }

    #[test]
    fn a_page_starts_its_value_scan_at_the_offset() {
        let store = WalkOnlyStore::with_keys(1_000);
        let realm = RealmId::generate();

        let (window, total) = store
            .scan_prefix_paged(&realm, b"usr:", 990, 200, 0)
            .expect("last page");

        assert_eq!(total, 1_000);
        assert_eq!(keys(&window), (990..1_000).map(key).collect::<Vec<_>>());
        assert_eq!(store.largest_scan.load(Ordering::SeqCst), 10);
    }

    #[test]
    fn a_page_past_the_end_reads_no_values() {
        let store = WalkOnlyStore::with_keys(1_000);
        let realm = RealmId::generate();

        let (window, total) = store
            .scan_prefix_paged(&realm, b"usr:", 5_000, 200, 0)
            .expect("page past the end");

        assert_eq!(keys(&window), Vec::<Vec<u8>>::new(), "no rows past the end");
        assert_eq!(total, 1_000);
        assert_eq!(store.scans.load(Ordering::SeqCst), 0, "no value scan");
    }

    #[test]
    fn a_zero_limit_page_is_empty_and_still_counts() {
        let store = WalkOnlyStore::with_keys(1_000);
        let realm = RealmId::generate();

        let (window, total) = store
            .scan_prefix_paged(&realm, b"usr:", 0, 0, 0)
            .expect("empty page");

        assert_eq!(keys(&window), Vec::<Vec<u8>>::new());
        assert_eq!(total, 1_000);
        assert_eq!(store.scans.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_capped_total_stops_walking_at_the_cap() {
        let store = WalkOnlyStore::with_keys(100_000);
        let realm = RealmId::generate();

        let (window, total) = store
            .scan_prefix_paged(&realm, b"usr:", 0, 200, 1_000)
            .expect("capped page");

        assert_eq!(total, 1_000);
        assert_eq!(window.len(), 200);
        assert_eq!(store.keys_walked.load(Ordering::SeqCst), 1_000);
    }

    #[test]
    fn a_capped_total_still_walks_to_a_page_beyond_the_cap() {
        let store = WalkOnlyStore::with_keys(5_000);
        let realm = RealmId::generate();

        let (window, total) = store
            .scan_prefix_paged(&realm, b"usr:", 2_000, 100, 1_000)
            .expect("page beyond the cap");

        assert_eq!(total, 1_000, "the reported total is capped");
        assert_eq!(keys(&window), (2_000..2_100).map(key).collect::<Vec<_>>());
    }

    #[test]
    fn count_prefix_walks_keys_and_stops_at_the_cap() {
        let store = WalkOnlyStore::with_keys(100_000);
        let realm = RealmId::generate();

        assert_eq!(
            store.count_prefix(&realm, b"usr:", 0).expect("count"),
            100_000
        );
        store.keys_walked.store(0, Ordering::SeqCst);
        assert_eq!(store.count_prefix(&realm, b"usr:", 10).expect("count"), 10);
        assert_eq!(store.keys_walked.load(Ordering::SeqCst), 10);
        assert_eq!(store.count_prefix(&realm, b"", 0).expect("count"), 0);
    }
}
