//! A paged prefix scan costs memory in proportion to the page, not to the
//! prefix (#447).
//!
//! `GET /admin/users` serves every page through
//! `StorageEngine::scan_prefix_paged`, which also reports the exact `total`.
//! Counting that total once collected every key under the prefix: about
//! 100 MB per page at 1,000,000 users. These tests measure the peak heap the
//! scan holds on the calling thread while it pages through 100,000 keys, with
//! the keys in the memtable, and in SSTs under a memtable overlay.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Peak live heap, scoped to the measuring thread ───────────────────────────

struct PeakAllocator;

thread_local! {
    /// Only the thread that sets this is measured. `const`-initialised with no
    /// destructor, so reading these from inside the allocator cannot allocate.
    static MEASURING: Cell<bool> = const { Cell::new(false) };
    /// Bytes this thread allocated and has not freed since measuring started.
    static LIVE: Cell<i64> = const { Cell::new(0) };
    /// The highest `LIVE` reached since measuring started.
    static PEAK: Cell<i64> = const { Cell::new(0) };
}

fn note(delta: i64) {
    // `try_with`: the allocator also runs during thread-local teardown.
    if MEASURING.try_with(Cell::get).unwrap_or(false) {
        let _ = LIVE.try_with(|live| {
            let now = live.get() + delta;
            live.set(now);
            let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
        });
    }
}

#[allow(clippy::cast_possible_wrap)]
fn bytes(n: usize) -> i64 {
    n as i64
}

unsafe impl GlobalAlloc for PeakAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(bytes(layout.size()));
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note(-bytes(layout.size()));
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(bytes(layout.size()));
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(bytes(new_size) - bytes(layout.size()));
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: PeakAllocator = PeakAllocator;

/// Runs `f` and returns its result with the peak heap it held on this thread
/// above what was live when it started.
fn peak_heap_during<T>(f: impl FnOnce() -> T) -> (T, i64) {
    LIVE.with(|live| live.set(0));
    PEAK.with(|peak| peak.set(0));
    MEASURING.with(|m| m.set(true));
    let out = f();
    MEASURING.with(|m| m.set(false));
    (out, PEAK.with(Cell::get))
}

// ── Fixture ──────────────────────────────────────────────────────────────────

/// Keys under the scanned prefix.
const KEYS: u32 = 100_000;
/// `MAX_PAGE_LIMIT`, the largest page the admin API serves.
const PAGE: u32 = 200;
/// The heap a 200-row page may hold. The page itself is about 20 KiB; one
/// collected copy of the 100,000 keys is several MiB.
const PAGE_BUDGET_BYTES: i64 = 1024 * 1024;

const PREFIX: &[u8] = b"usr:";

fn key(i: u32) -> Vec<u8> {
    format!("usr:{i:08}").into_bytes()
}

fn value(i: u32) -> Vec<u8> {
    format!("{{\"id\":{i:08},\"name\":\"user\"}}").into_bytes()
}

fn open(dir: &tempfile::TempDir) -> EmbeddedStorageEngine {
    let mut config = StorageConfig::dev(dir.path().to_path_buf());
    // Nothing flushes unless a test asks for it.
    config.set_memtable_flush_bytes(1 << 30);
    EmbeddedStorageEngine::open(config).expect("open engine")
}

fn write_keys(engine: &EmbeddedStorageEngine, realm: &RealmId, range: std::ops::Range<u32>) {
    let ids: Vec<u32> = range.collect();
    for chunk in ids.chunks(1_000) {
        let batch: Vec<(Vec<u8>, Vec<u8>)> = chunk.iter().map(|&i| (key(i), value(i))).collect();
        engine.put_batch(realm, &batch).expect("put_batch");
    }
}

/// Pages through `engine` at `offset` and checks the page's memory and rows.
fn assert_page_is_bounded(
    engine: &EmbeddedStorageEngine,
    realm: &RealmId,
    offset: u64,
    expected_keys: &[Vec<u8>],
    expected_total: u64,
) {
    let (result, peak) =
        peak_heap_during(|| engine.scan_prefix_paged(realm, PREFIX, offset, PAGE, 0));
    let (window, total) = result.expect("scan_prefix_paged");

    assert_eq!(
        total, expected_total,
        "total counts every key under the prefix"
    );
    let keys: Vec<&[u8]> = window.iter().map(|e| e.key.as_slice()).collect();
    let expected: Vec<&[u8]> = expected_keys.iter().map(Vec::as_slice).collect();
    assert_eq!(keys, expected, "the page at offset {offset}");
    assert!(
        peak <= PAGE_BUDGET_BYTES,
        "a {PAGE}-row page at offset {offset} over {expected_total} keys held {peak} bytes \
         of heap at its peak (budget {PAGE_BUDGET_BYTES}): the scan grows with the prefix, \
         not with the page"
    );
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn a_page_over_memtable_keys_holds_heap_for_the_page_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = open(&dir);
    let realm = RealmId::generate();
    write_keys(&engine, &realm, 0..KEYS);
    // A neighbouring realm's keys sort next to this one's and must not count.
    write_keys(&engine, &RealmId::generate(), 0..1_000);

    let first: Vec<Vec<u8>> = (0..PAGE).map(key).collect();
    assert_page_is_bounded(&engine, &realm, 0, &first, u64::from(KEYS));

    let last_offset = KEYS - PAGE;
    let last: Vec<Vec<u8>> = (last_offset..KEYS).map(key).collect();
    assert_page_is_bounded(
        &engine,
        &realm,
        u64::from(last_offset),
        &last,
        u64::from(KEYS),
    );
}

#[test]
fn a_page_over_sst_keys_under_a_memtable_overlay_holds_heap_for_the_page_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = open(&dir);
    let realm = RealmId::generate();

    // Two SSTs, then a memtable that deletes every tenth of the first 2,000
    // keys and rewrites key 1: the scan merges three sources, newest first.
    write_keys(&engine, &realm, 0..KEYS / 2);
    engine.flush_memtable().expect("flush");
    write_keys(&engine, &realm, KEYS / 2..KEYS);
    engine.flush_memtable().expect("flush");
    for i in (0..2_000).step_by(10) {
        engine.delete(&realm, &key(i)).expect("delete");
    }
    engine.put(&realm, &key(1), b"rewritten").expect("put");

    let live: Vec<Vec<u8>> = (0..KEYS)
        .filter(|i| *i >= 2_000 || i % 10 != 0)
        .map(key)
        .collect();
    let expected_total = live.len() as u64;

    // The first page warms the block cache, whose decrypted blocks are not
    // the scan's own memory; the measured pages read through a warm cache.
    let _ = engine
        .scan_prefix_paged(&realm, PREFIX, 0, PAGE, 0)
        .expect("warm");
    let (warm, _) = engine
        .scan_prefix_paged(&realm, PREFIX, 0, PAGE, 0)
        .expect("warm page");
    let rewritten = warm
        .iter()
        .find(|e| e.key == key(1))
        .expect("key 1 on page 1");
    assert_eq!(
        rewritten.value, b"rewritten",
        "the memtable's newer value wins"
    );

    assert_page_is_bounded(&engine, &realm, 0, &live[..PAGE as usize], expected_total);
    let mid = live.len() / 2;
    assert_page_is_bounded(
        &engine,
        &realm,
        mid as u64,
        &live[mid..mid + PAGE as usize],
        expected_total,
    );
}
