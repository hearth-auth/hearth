//! `hearth::core::EpochCell`'s hot-path contract, checked in a process that
//! nothing else pins in (task 26.5).
//!
//! One test, deliberately. A second test on another thread of this binary
//! could be pinned at the wrong moment and hold a grace period open, which is
//! exactly what the strict assertions below rule out. Everything that also
//! holds in a shared process is covered by the cell's unit tests in
//! `src/core/epoch_cell.rs`.
//!
//! 1. With nothing writing, a warm load allocates nothing (`CLAUDE.md` hot-path
//!    rule 1), including after writes have left garbage for the epoch
//!    collector.
//! 2. With no reader pinned, a write releases the value it replaced before it
//!    returns, on the writing thread.
//! 3. A reader pinned before a write keeps the replaced values alive, and once
//!    it unpins, `reclaim` releases every one of them — on the writer's
//!    thread, never the reader's.
//! 4. Work other code defers to `crossbeam-epoch`'s default collector — where
//!    `crossbeam-skiplist` frees memtable nodes — never runs inside a load and
//!    never costs one an allocation: the cells have a collector of their own.
//! 5. While another thread writes, a load's share of the cells' collector
//!    costs at most one allocation per 1,024 loads (`docs/dev/ARCHITECTURE.md` §3.2) —
//!    measured with the writer running, not after it has stopped.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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

// ── Concurrency that must overlap the measurement ────────────────────────────

/// Loads measured while another thread works: at least this many, and more
/// until that thread has made [`MIN_CONCURRENT_OPS`] steps of progress inside
/// the measured window, so the window provably overlapped its work.
const MEASURED_LOADS: u64 = 1_000_000;
/// Steps the other thread must complete inside the measured window. Progress
/// is counted, not timed, so a slow or loaded host lengthens the window
/// instead of failing it.
const MIN_CONCURRENT_OPS: u64 = 2_000;
/// A window this many times [`MEASURED_LOADS`] that has still not overlapped
/// the other thread's work means that thread is not running at all.
const MAX_LOAD_FACTOR: u64 = 200;

/// Runs `load` on this thread in a counted window that overlaps at least
/// [`MIN_CONCURRENT_OPS`] steps of `progress`, advanced by another thread.
/// Returns the loads made and the allocations they cost.
fn loads_overlapping(progress: &AtomicU64, mut load: impl FnMut()) -> (u64, usize) {
    let mut loads = 0_u64;
    let allocated = allocations_during(|| {
        let start = progress.load(Ordering::Relaxed);
        loop {
            for _ in 0..1_024 {
                load();
            }
            loads += 1_024;
            let overlapped = progress.load(Ordering::Relaxed) - start >= MIN_CONCURRENT_OPS;
            if (loads >= MEASURED_LOADS && overlapped) || loads >= MEASURED_LOADS * MAX_LOAD_FACTOR
            {
                break;
            }
        }
        let steps = progress.load(Ordering::Relaxed) - start;
        assert!(
            steps >= MIN_CONCURRENT_OPS,
            "the concurrent thread made only {steps} steps during {loads} loads"
        );
    });
    (loads, allocated)
}

/// Raises `stop` when dropped, so a failed assertion inside a
/// `thread::scope` still ends the scope's worker instead of waiting on it.
struct StopOnDrop<'a>(&'a AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Set by work deferred to `crossbeam-epoch`'s default collector when it runs
/// on the measuring thread inside a measured window.
static FOREIGN_WORK_ON_READER: AtomicUsize = AtomicUsize::new(0);

fn note_if_on_measuring_thread() {
    // `try_with`: a deferred function can run while some thread's
    // thread-locals are being torn down.
    if COUNTING.try_with(Cell::get).unwrap_or(false) {
        FOREIGN_WORK_ON_READER.fetch_add(1, Ordering::Relaxed);
    }
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
    // The phases run in this order, in this one test: 2 and 3 need a process
    // in which no other thread is pinned, and 4 and 5 start threads that pin.
    let cache = EpochCell::from_pointee(HashMap::from([(7_u64, Arc::new(String::from("seven")))]));
    warm_loads_allocate_nothing_while_nothing_writes(&cache);
    let log = Arc::new(DropLog::default());
    let cell = writes_release_what_they_replace_before_returning(&log);
    a_pinned_reader_holds_the_grace_period_open(cell, &log);
    other_codes_epoch_garbage_never_reaches_a_load(&cache);
    a_running_writer_costs_at_most_one_allocation_per_1024_loads();
}

type Cache = EpochCell<HashMap<u64, Arc<String>>>;

/// 1. With nothing writing, a warm load allocates nothing.
fn warm_loads_allocate_nothing_while_nothing_writes(cache: &Cache) {
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
}

/// 2. A write releases what it replaced before it returns, on its own thread.
fn writes_release_what_they_replace_before_returning(log: &Arc<DropLog>) -> EpochCell<Logged> {
    let cell = EpochCell::from_pointee(Logged::new(0, log));
    cell.store(Arc::new(Logged::new(1, log)));
    assert_eq!(
        log.ids(),
        vec![0],
        "with no reader pinned, store must release its predecessor before returning"
    );
    cell.rcu(|current| Logged::new(current.id + 1, log));
    assert_eq!(log.ids(), vec![0, 1], "and so must rcu");
    let me = thread::current().id();
    assert!(
        log.threads().iter().all(|t| *t == me),
        "a replaced value must be released on the thread that wrote"
    );
    cell
}

/// 3. A pinned reader holds the grace period open; once it unpins, `reclaim`
///    releases what it held back, on the writer's thread.
fn a_pinned_reader_holds_the_grace_period_open(cell: EpochCell<Logged>, log: &Arc<DropLog>) {
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
    shared.store(Arc::new(Logged::new(3, log)));
    shared.store(Arc::new(Logged::new(4, log)));
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

    shared.store(Arc::new(Logged::new(5, log)));
    assert_eq!(log.ids(), vec![0, 1, 2, 3, 4]);
    assert_eq!(shared.load().id, 5);
    let me = thread::current().id();
    assert!(
        log.threads().iter().all(|t| *t == me),
        "every release ran on the writing thread, never on the reader"
    );
}

/// 4. Other code's epoch garbage never reaches a load.
///
/// `crossbeam-skiplist` defers the memtable's node frees to `crossbeam-epoch`'s
/// default collector. A thread that pins that collector runs a slice of its
/// pending work every 128 pins; an `EpochCell` load must never be that thread.
fn other_codes_epoch_garbage_never_reaches_a_load(cache: &Cache) {
    // Warm up first: the cells' own collector retires what phases 2 and 3
    // left (their bags, the exited reader's participant) outside the window.
    for _ in 0..10_000 {
        black_box(cache.load().get(&7).map(Arc::clone));
    }
    let deferred = AtomicU64::new(0);
    let stop = AtomicBool::new(false);
    let (loads, allocated) = thread::scope(|s| {
        s.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                let guard = crossbeam_epoch::pin();
                guard.defer(note_if_on_measuring_thread);
                guard.flush();
                deferred.fetch_add(1, Ordering::Relaxed);
            }
        });
        let _stop = StopOnDrop(&stop);
        loads_overlapping(&deferred, || {
            black_box(cache.load().get(&7).map(Arc::clone));
        })
    });
    assert_eq!(
        FOREIGN_WORK_ON_READER.load(Ordering::Relaxed),
        0,
        "an EpochCell load ran work another thread deferred to crossbeam-epoch's default collector"
    );
    assert_eq!(
        allocated, 0,
        "work deferred to crossbeam-epoch's default collector cost EpochCell loads \
         {allocated} allocations in {loads} loads"
    );
}

/// 5. With a writer running, at most one allocation per 1,024 loads.
///
/// Every 128th pin runs a slice of the cells' own collector: it retires up to
/// eight bags of expired callbacks, and the queue nodes of 64 retired bags go
/// back to the collector in one allocation. While `EpochCell` writes keep
/// producing bags, that is the whole of a load's allocation, and it is bounded
/// by the pins, not by how hard anything writes.
fn a_running_writer_costs_at_most_one_allocation_per_1024_loads() {
    let counter = EpochCell::from_pointee(0_u64);
    let writes = AtomicU64::new(0);
    let stop = AtomicBool::new(false);
    let (loads, allocated) = thread::scope(|s| {
        s.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                counter.rcu(|n| n + 1);
                writes.fetch_add(1, Ordering::Relaxed);
            }
        });
        let _stop = StopOnDrop(&stop);
        loads_overlapping(&writes, || {
            black_box(*counter.load());
        })
    });
    // The bound: 8 bags per 128 loads and 64 retired bags per allocation,
    // plus one for the entries this thread's bag already held when the window
    // opened, and one for the window's partial collections and any exited
    // thread's participant a collection unlinks (one entry each).
    let bound = usize::try_from(loads / 1_024 + 2).expect("the bound fits a usize");
    assert!(
        allocated <= bound,
        "with a writer running, {loads} loads allocated {allocated} times, more than \
         the collector's bound of one per 1,024 loads ({bound})"
    );
    assert_eq!(
        *counter.load(),
        writes.load(Ordering::Relaxed),
        "every write landed"
    );
}
