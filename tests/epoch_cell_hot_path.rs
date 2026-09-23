//! `hearth::core::EpochCell`'s hot-path contract, checked in a process that
//! nothing else pins in (task 26.5).
//!
//! One test, deliberately. A second test on another thread of this binary
//! could be pinned at the wrong moment and hold a grace period open, which is
//! exactly what the strict assertions below rule out. Everything that also
//! holds in a shared process is covered by the cell's unit tests in
//! `src/core/epoch_cell.rs`.
//!
//! 1. A warm load allocates nothing (`CLAUDE.md` hot-path rule 1), including
//!    after writes have left garbage for the epoch collector.
//! 2. With no reader pinned, a write releases the value it replaced before it
//!    returns, on the writing thread.
//! 3. A reader pinned before a write keeps the replaced values alive, and once
//!    it unpins, `reclaim` releases every one of them — on the writer's
//!    thread, never the reader's.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, ThreadId};

use hearth::core::EpochCell;

// ── Allocation counting, scoped to the measuring thread ──────────────────────

struct CountingAllocator;

thread_local! {
    /// Only the thread that sets this is counted, so the harness's own
    /// threads never contribute. `const`-initialised with no destructor, so
    /// reading it from inside the allocator cannot itself allocate.
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

fn note_allocation() {
    // `try_with`: the allocator also runs during thread-local teardown.
    if COUNTING.try_with(Cell::get).unwrap_or(false) {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_allocation();
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_allocation();
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note_allocation();
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Heap allocations `f` makes on this thread.
fn allocations_during(f: impl FnOnce()) -> usize {
    ALLOCATIONS.store(0, Ordering::SeqCst);
    COUNTING.with(|c| c.set(true));
    f();
    COUNTING.with(|c| c.set(false));
    ALLOCATIONS.load(Ordering::SeqCst)
}

// ── A value that records where it was released ───────────────────────────────

/// Records every drop, and on which thread it ran.
#[derive(Default)]
struct DropLog {
    dropped: Mutex<Vec<(u64, ThreadId)>>,
}

impl DropLog {
    fn ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .dropped
            .lock()
            .expect("drop log")
            .iter()
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids
    }

    fn threads(&self) -> Vec<ThreadId> {
        self.dropped
            .lock()
            .expect("drop log")
            .iter()
            .map(|(_, thread)| *thread)
            .collect()
    }
}

struct Logged {
    id: u64,
    log: Arc<DropLog>,
}

impl Logged {
    fn new(id: u64, log: &Arc<DropLog>) -> Self {
        Self {
            id,
            log: Arc::clone(log),
        }
    }
}

impl Drop for Logged {
    fn drop(&mut self) {
        self.log
            .dropped
            .lock()
            .expect("drop log")
            .push((self.id, thread::current().id()));
    }
}

#[test]
fn epoch_cell_meets_its_hot_path_contract_in_a_quiet_process() {
    // ── 1. A warm load allocates nothing ──────────────────────────────────────
    let cache = EpochCell::from_pointee(HashMap::from([(7_u64, Arc::new(String::from("seven")))]));
    // Writes leave retired values and epoch bags behind for the collector.
    for round in 0..16_u64 {
        cache.rcu(|current| {
            let mut next = current.clone();
            next.insert(round, Arc::new(round.to_string()));
            next
        });
    }
    // Warm up: registers this thread with the collector (its one allocation)
    // and lets the periodic collection inside `pin()` drain what the writes
    // left, the way a request thread's steady state does.
    for _ in 0..5_000 {
        black_box(cache.load().get(&7).map(Arc::clone));
    }
    let allocated = allocations_during(|| {
        for _ in 0..10_000 {
            black_box(cache.load().get(&7).map(Arc::clone));
            black_box(cache.load_full());
        }
    });
    assert_eq!(
        allocated, 0,
        "a warm EpochCell load allocated {allocated} times in 20,000 reads"
    );

    // ── 2. A write releases what it replaced before it returns ──────────────
    let log = Arc::new(DropLog::default());
    let cell = EpochCell::from_pointee(Logged::new(0, &log));
    cell.store(Arc::new(Logged::new(1, &log)));
    assert_eq!(
        log.ids(),
        vec![0],
        "with no reader pinned, store must release its predecessor before returning"
    );
    cell.rcu(|current| Logged::new(current.id + 1, &log));
    assert_eq!(log.ids(), vec![0, 1], "and so must rcu");
    let me = thread::current().id();
    assert!(
        log.threads().iter().all(|t| *t == me),
        "a replaced value must be released on the thread that wrote"
    );

    // ── 3. A pinned reader holds the grace period open ──────────────────────
    let shared = Arc::new(cell);
    let (pinned_tx, pinned_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let reader = thread::spawn({
        let shared = Arc::clone(&shared);
        move || {
            let guard = shared.load();
            pinned_tx.send(guard.id).expect("writer is listening");
            release_rx.recv().expect("writer releases the reader");
            guard.id
        }
    });

    assert_eq!(pinned_rx.recv().expect("reader pinned"), 2);
    shared.store(Arc::new(Logged::new(3, &log)));
    shared.store(Arc::new(Logged::new(4, &log)));
    assert_eq!(
        log.ids(),
        vec![0, 1],
        "no value may be released while a reader pinned before the writes is still pinned"
    );

    release_tx.send(()).expect("reader is waiting");
    assert_eq!(reader.join().expect("reader thread"), 2);

    // No further write needed: `reclaim` is how a rarely written cell (the
    // memtable after a flush) releases what its last write had to leave.
    shared.reclaim();
    assert_eq!(
        log.ids(),
        vec![0, 1, 2, 3],
        "once the reader unpinned, reclaim must release everything it held back"
    );

    shared.store(Arc::new(Logged::new(5, &log)));
    assert_eq!(log.ids(), vec![0, 1, 2, 3, 4]);
    assert_eq!(shared.load().id, 5);
    assert!(
        log.threads().iter().all(|t| *t == me),
        "every release ran on the writing thread, never on the reader"
    );
}
