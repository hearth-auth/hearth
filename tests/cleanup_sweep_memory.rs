//! A cleanup sweep costs memory in proportion to what it deletes, not to the
//! rows it keeps (#445).
//!
//! Every five minutes the periodic sweep walks the single-use markers, grant
//! families and other expiring rows of each realm. It collected every row
//! under each prefix first: one `consumed:refresh:` marker per refresh-token
//! rotation, kept for the refresh token's lifetime (7 days by default). At 78
//! rotations a second that is 280,000 markers an hour, all copied into one
//! `Vec` (and a `BTreeMap` before it) on every sweep. These tests measure the
//! peak heap a sweep holds on the calling thread while it walks 100,000 live
//! markers, with the markers in the memtable and in SSTs.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

use hearth::core::RealmId;
use hearth::storage::StorageEngine;

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

/// Markers written: about 22 minutes of rotations at the 78 refreshes a
/// second of the AWS soak (#445).
const MARKERS: u32 = 102_500;
/// One marker in this many has expired; the rest are live. The expired ones
/// are spread through the key range, so the walk meets both throughout.
const EXPIRED_EVERY: u32 = 41;
/// `MARKERS / EXPIRED_EVERY`: the markers the sweep must delete.
const EXPIRED_MARKERS: u32 = 2_500;
/// The heap one sweep may hold. A sweep that collects the prefix holds about
/// 38 MB here; a streaming one about 430 KiB (the rows it picks for deletion,
/// 512 at a time, and one decoded block per SST).
const SWEEP_BUDGET_BYTES: i64 = 1024 * 1024;

/// A `consumed:refresh:` marker key, as `claim_single_use` writes it for a
/// rotated refresh token (a SHA-256 hex digest).
fn marker(i: u32) -> Vec<u8> {
    format!("consumed:refresh:{i:064x}").into_bytes()
}

fn is_expired(i: u32) -> bool {
    i.is_multiple_of(EXPIRED_EVERY)
}

fn now_secs() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs();
    i64::try_from(secs).expect("seconds fit in i64")
}

/// Writes markers `range`, each holding its expiry as an 8-byte little-endian
/// Unix-seconds `i64`: an hour ago for the expired ones, in 7 days for the
/// live ones.
fn write_markers(storage: &dyn StorageEngine, realm: &RealmId, range: std::ops::Range<u32>) {
    let now = now_secs();
    let ids: Vec<u32> = range.collect();
    for chunk in ids.chunks(1_000) {
        let batch: Vec<(Vec<u8>, Vec<u8>)> = chunk
            .iter()
            .map(|&i| {
                let expires_at = if is_expired(i) {
                    now - 3_600
                } else {
                    now + 7 * 86_400
                };
                (marker(i), expires_at.to_le_bytes().to_vec())
            })
            .collect();
        storage.put_batch(realm, &batch).expect("put_batch");
    }
}

fn assert_sweep_is_bounded(harness: &common::TestHarness, realm: &RealmId) {
    let (stats, peak) = peak_heap_during(|| harness.identity().sweep_expired(realm));
    let stats = stats.expect("sweep_expired");

    assert_eq!(stats.errors, 0, "the sweep reports no error");
    assert_eq!(
        stats.consumed_markers_deleted,
        u64::from(EXPIRED_MARKERS),
        "every expired marker is deleted"
    );
    let storage = harness.storage();
    for i in (0..MARKERS).step_by(7) {
        let found = storage.get(realm, &marker(i)).expect("get").is_some();
        assert_eq!(
            found,
            !is_expired(i),
            "marker {i}: expired ones go, live ones stay"
        );
    }
    assert!(
        peak <= SWEEP_BUDGET_BYTES,
        "one sweep over {MARKERS} markers held {peak} bytes of heap at its peak \
         (budget {SWEEP_BUDGET_BYTES}): the sweep grows with the rows it keeps"
    );
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_sweep_over_memtable_markers_holds_heap_for_what_it_deletes() {
    let harness = common::TestHarness::in_process().await.expect("harness");
    let realm = RealmId::generate();
    write_markers(harness.storage(), &realm, 0..MARKERS);

    assert_sweep_is_bounded(&harness, &realm);
}

#[tokio::test]
async fn a_sweep_over_sst_markers_holds_heap_for_what_it_deletes() {
    let harness = common::TestHarness::in_process().await.expect("harness");
    let realm = RealmId::generate();
    let storage = harness.storage();

    // Two SSTs and a memtable overlay: the sweep merges three sources.
    write_markers(storage, &realm, 0..MARKERS / 2);
    storage.flush_memtable().expect("flush");
    write_markers(storage, &realm, MARKERS / 2..MARKERS);
    storage.flush_memtable().expect("flush");
    // The overlay rewrites a live marker (it stays live) and re-expires the
    // first expired one (still expired: one deletion, not two).
    write_markers(storage, &realm, 0..2);

    assert_sweep_is_bounded(&harness, &realm);
}
