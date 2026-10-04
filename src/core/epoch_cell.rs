//! [`EpochCell`] — a lock-free atomic `Arc<T>` with epoch-based reclamation,
//! the hot-path replacement for `ArcSwap` (task 26.5).
//!
//! # Why this exists
//!
//! `arc-swap` 1.9.2 corrupts the heap under the `load` + `rcu` pattern this
//! codebase used: 3 failures in 150 loaded runs under `MALLOC_CHECK_=3` (two
//! `SIGSEGV`, one `free(): invalid size`), 0 once the primitive was replaced.
//! See `https://github.com/hearth-auth/hearth/blob/4d9dda1f5b514891e90dadeffb03d1a026af4e51/reports/arc-swap-use-after-free-2026-09-21.md`. [`SwapCell`] fixed the
//! sites off the hot path with a read lock. The hot path — `validate_token`,
//! `lookup_session` and every storage read — may not take one (`CLAUDE.md`,
//! hot-path rule 3), so this cell uses epoch-based reclamation from
//! `crossbeam-epoch`, the mechanism that rule names.
//!
//! # How it works
//!
//! The cell stores the current value as the raw pointer of an `Arc<T>`
//! (`Arc::into_raw`) in an `AtomicPtr`, and owns that pointer's strong count.
//!
//! * **A read** ([`EpochCell::load`]) pins the thread in the cells' epoch
//!   collector and reads through the pointer: no lock, no syscall and no
//!   write to the shared refcount. What it can cost in allocation is below.
//!   [`EpochCell::load_full`] also bumps the refcount — an atomic increment,
//!   not an allocation — for a caller that keeps the value.
//! * **A write** ([`EpochCell::store`], [`EpochCell::rcu`]) swaps or
//!   compare-and-swaps the pointer and *retires* the `Arc` it replaced: the
//!   cell keeps it on a retired list and registers an epoch callback that does
//!   nothing but raise a flag. `crossbeam-epoch` runs that callback only after
//!   every thread that was pinned in the collector when it was registered has
//!   unpinned — the grace period after which no reader can still be reading
//!   through the old pointer.
//! * **The writer releases** retired values whose flag is up.
//!   `crossbeam-epoch` runs deferred callbacks inside whichever thread's
//!   `pin()` collects them, which on the hot path is usually a reader, so the
//!   callback must not be the thing that frees. The flag keeps the destructor
//!   of a replaced value — a whole cache map, a flushed memtable, a list of SST
//!   readers — off the reader and on the write path that replaced it. (An
//!   `Arc` a reader took with `load_full` is the reader's to drop, as with any
//!   `Arc`.)
//!
//! A write nudges the collector a bounded number of times
//! (`RECLAIM_NUDGES`), so in the common case the value it replaced is
//! released before the write returns. A value whose grace period is still
//! open — some thread stayed pinned throughout, typically one preempted
//! mid-read — is released by a later write to the same cell, by an explicit
//! [`EpochCell::reclaim`], or when the cell drops. Measured with 8 to 15
//! readers pinning in tight loops on a loaded 16-core host, 82–99.5% of writes
//! released their predecessor before returning, and the worst backlog was 42
//! values after 2,000 back-to-back writes.
//!
//! # The collector, and what a read costs
//!
//! All `EpochCell`s in the process share one collector, `COLLECTOR`, rather
//! than `crossbeam-epoch`'s default one. Pinning writes only the thread's own
//! participant, except that every 128th pin on a thread also runs a slice of
//! the collector's pending work — `crossbeam-epoch`'s amortised collection,
//! which no pin can opt out of. The slice tries to advance the epoch and
//! retires up to eight bags of expired callbacks. Retiring a bag runs its
//! callbacks — here they only raise a flag or free the collector's own
//! bookkeeping (a queue node, a flag, an exited thread's participant), never
//! a replaced value — and queues the bag's emptied queue node for release in
//! the thread's own bag of deferred work. When that bag is full, at 64
//! entries, it moves to the collector's queue, which allocates one queue
//! node. So a load's allocation is amortised and bounded, not zero:
//!
//! * With no cell being written (and no thread that used one exiting), a warm
//!   load allocates nothing.
//! * While cells are being written, a thread's loads allocate at most once per
//!   1,024 (eight bags per 128 pins, 64 bags per allocation), however hard
//!   anything writes. Measured on a 16-core host with a writer storing in a
//!   tight loop, about 65,000 writes during the window: 13–16 allocations in
//!   2,000,000 loads.
//!
//! `tests/epoch_cell_hot_path.rs` gates both, the second with the writer
//! running during the measurement. `docs/dev/ARCHITECTURE.md` §3.2 records this
//! bookkeeping as the one allocation the hot path permits.
//!
//! A separate collector keeps everything else out of that slice. On the
//! default collector a load also ran other crates' deferred work:
//! `crossbeam-skiplist` frees memtable nodes there, and with one thread
//! inserting and removing skiplist entries, a reader made about 160,000 frees
//! and 20 allocations in 2,000,000 loads, where it now makes none. It also
//! keeps grace periods apart: a guard held on the default collector, a
//! skiplist read say, cannot hold back a value an `EpochCell` replaced, and an
//! [`EpochGuard`] cannot hold back the skiplist's garbage.
//!
//! # Rules for callers
//!
//! * Hold an [`EpochGuard`] only across a short, non-blocking read. While any
//!   thread is pinned in the cells' collector, *no* value any `EpochCell`
//!   retired can be released, so a guard held across I/O, a lock or a long
//!   scan stalls reclamation for every cell. Use [`EpochCell::load_full`] for
//!   anything longer.
//! * An [`EpochGuard`] is `!Send`: the pin belongs to the thread that took it.
//!
//! # `unsafe`
//!
//! The four `unsafe` blocks below are the `Arc` raw-pointer round trip and the
//! pinned dereference; each states the invariant it relies on. The grace
//! period itself is `crossbeam-epoch`'s documented guarantee for
//! `Guard::defer`: the callback "won't be executed until all currently pinned
//! threads get unpinned" — pinned in the collector the guard belongs to,
//! which is why a load and the write that retires what it read must pin the
//! same one.
//!
//! [`SwapCell`]: crate::core::SwapCell

use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use crossbeam_epoch as epoch;

/// The collector every `EpochCell` pins and retires into: its own, never
/// `crossbeam-epoch`'s default one. See the module docs for why.
///
/// Soundness rests on one invariant here: [`EpochCell::load`] and the write
/// that retires a value pin this same collector (through [`pin`]), so the
/// grace period a write waits for covers every reader that could hold the
/// value it replaced.
static COLLECTOR: LazyLock<epoch::Collector> = LazyLock::new(epoch::Collector::new);

thread_local! {
    /// This thread's participant in [`COLLECTOR`], registered on first use.
    static PARTICIPANT: epoch::LocalHandle = COLLECTOR.register();
}

/// Pins this thread in [`COLLECTOR`].
#[inline]
fn pin() -> epoch::Guard {
    PARTICIPANT
        .try_with(epoch::LocalHandle::pin)
        // Only while this thread's thread-locals are being destroyed, as
        // `crossbeam_epoch::pin` does: a participant registered for this one
        // guard, which unregisters itself when the guard drops.
        .unwrap_or_else(|_| COLLECTOR.register().pin())
}

/// Whether this thread is pinned in [`COLLECTOR`] — by a guard further up
/// its stack, since [`pin`] is the only way in.
fn is_pinned() -> bool {
    PARTICIPANT
        .try_with(epoch::LocalHandle::is_pinned)
        .unwrap_or(false)
}

/// How many times a write nudges the epoch collector, waiting for the grace
/// period of the value it just replaced, before leaving that value for a later
/// write to release.
///
/// Each nudge is one `pin()` + `flush()`: it hands this thread's deferred
/// callbacks to the collector's queue, tries to advance the collector's epoch
/// by one and runs the callbacks whose grace period has ended. Two advances
/// end a grace period; the other two absorb advances refused because some
/// thread was mid-read in the previous epoch.
const RECLAIM_NUDGES: usize = 4;

/// A cell holding an `Arc<T>` that readers load without a lock or a syscall,
/// and writers replace wholesale.
///
/// The epoch-reclaimed counterpart of [`SwapCell`](crate::core::SwapCell), for
/// the hot path, where `SwapCell`'s read lock is not allowed. See the module
/// docs for how reclamation works, for what a load can cost in allocation
/// (amortised, at most one per 1,024 loads on a thread), and for the one rule
/// callers must keep: drop an [`EpochGuard`] promptly.
pub struct EpochCell<T> {
    /// `Arc::into_raw` of the current value. Never null; the cell owns one
    /// strong count for it.
    current: AtomicPtr<T>,
    /// Values replaced by a write whose grace period may still be open.
    retired: Mutex<Vec<Retired<T>>>,
    /// The cell owns `T` values and shares them across threads exactly as an
    /// `Arc<T>` does, so it takes `Arc<T>`'s auto traits and drop check.
    _owns: PhantomData<Arc<T>>,
}

/// A value a write replaced, held until no reader can still reach it.
struct Retired<T> {
    /// Held only so it can be dropped once the grace period ends.
    _value: Arc<T>,
    /// Raised by the epoch callback registered when the value was retired.
    grace_elapsed: Arc<AtomicBool>,
}

impl<T> Retired<T> {
    fn grace_elapsed(&self) -> bool {
        self.grace_elapsed.load(Ordering::Acquire)
    }
}

/// A pinned, borrowed view of the value an [`EpochCell`] held when it was
/// loaded.
///
/// Dereferences to that value for as long as the guard lives, even after a
/// writer replaces it. The guard keeps its thread pinned, which holds back
/// every `EpochCell`'s reclamation, so drop it promptly — see the module
/// docs.
#[must_use = "an EpochGuard pins the thread until it is dropped"]
pub struct EpochGuard<'a, T> {
    /// The loaded value, valid while `pin` lives.
    ptr: *const T,
    /// Keeps the loaded value's grace period open.
    pin: epoch::Guard,
    /// Ties the guard to the cell that owns the value.
    _cell: PhantomData<&'a EpochCell<T>>,
}

impl<T> Deref for EpochGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: `ptr` was loaded from an `EpochCell` after `pin` pinned this
        // thread in `COLLECTOR`, the collector every write retires into. The
        // cell only ever holds non-null `Arc::into_raw` pointers and owns a
        // strong count for each: while it is current, and on the retired list
        // after a write replaces it. A retired value is dropped only after its
        // grace-period flag is raised, and `crossbeam-epoch` runs the callback
        // that raises it only once every thread pinned in `COLLECTOR` at
        // retirement has unpinned — this one included, and it cannot unpin
        // before `pin` drops. The borrow `'a` on the cell rules out the cell
        // itself dropping first. So the value stays allocated for as long as
        // the returned reference, which cannot outlive `self`. The cell never
        // hands out `&mut T` to a published value, so a shared reference is
        // sound; interior mutability, such as the hot tier's atomic reference
        // bits, goes through `UnsafeCell` as it would behind any `&T`.
        unsafe { &*self.ptr }
    }
}

impl<T: fmt::Debug> fmt::Debug for EpochGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<T> EpochCell<T> {
    /// Creates a cell owning `value`.
    #[must_use]
    pub fn from_pointee(value: T) -> Self {
        Self::from_arc(Arc::new(value))
    }

    /// Creates a cell from an already-shared `value`.
    #[must_use]
    pub fn from_arc(value: Arc<T>) -> Self {
        Self {
            current: AtomicPtr::new(Arc::into_raw(value).cast_mut()),
            retired: Mutex::new(Vec::new()),
            _owns: PhantomData,
        }
    }

    /// Returns a pinned view of the current value.
    ///
    /// Takes no lock and makes no syscall, and the read allocates nothing
    /// itself. Every 128th load on a thread also runs a slice of the cells'
    /// epoch collector, which allocates at most once per 1,024 loads on that
    /// thread, and only while cells are being written (or a thread that used
    /// one exits) — see the module docs.
    /// The guard must be dropped promptly: hold it across a short read only,
    /// never across I/O, a lock or a long scan — use
    /// [`load_full`](Self::load_full) for those.
    #[inline]
    pub fn load(&self) -> EpochGuard<'_, T> {
        let pin = pin();
        // Acquire pairs with the writer's release, making the value's contents
        // visible. Loaded after pinning, so the pin covers it.
        let ptr = self.current.load(Ordering::Acquire);
        EpochGuard {
            ptr,
            pin,
            _cell: PhantomData,
        }
    }

    /// Returns the current value as an owned `Arc`.
    ///
    /// One atomic refcount increment on top of [`load`](Self::load), which it
    /// is otherwise identical to, allocation included. The `Arc` does not pin
    /// the thread, so it may be held for as long as the caller likes.
    #[must_use]
    pub fn load_full(&self) -> Arc<T> {
        let guard = self.load();
        // SAFETY: `guard.ptr` came from `Arc::into_raw`, and for as long as
        // `guard` pins this thread the strong count the cell (or its retired
        // list) owns for it cannot be released — the argument in
        // `EpochGuard::deref`. The count is therefore at least one throughout
        // this block, so incrementing it and adopting the increment with
        // `from_raw` hands the caller an `Arc` of its own.
        unsafe {
            Arc::increment_strong_count(guard.ptr);
            Arc::from_raw(guard.ptr)
        }
    }

    /// Replaces the current value with `value`.
    ///
    /// Readers already holding the previous value keep reading it; readers
    /// arriving after the store see `value`. The previous value is released on
    /// this thread once no reader can still hold it — before this call returns
    /// in the common case.
    pub fn store(&self, value: Arc<T>) {
        let next = Arc::into_raw(value).cast_mut();
        let pin = pin();
        let prev = self.current.swap(next, Ordering::AcqRel);
        self.retire(prev, pin);
    }

    /// Replaces the value with `f(current)`.
    ///
    /// A compare-and-swap loop, as `ArcSwap::rcu` was: if another write lands
    /// between reading the current value and publishing `f`'s result, the
    /// result is discarded and `f` runs again against the value that write
    /// installed. So `f` may run more than once, whatever it reads — a
    /// generation counter, say — is re-read on every attempt, and no update is
    /// ever lost.
    pub fn rcu<F>(&self, mut f: F)
    where
        F: FnMut(&T) -> T,
    {
        let mut current = self.load();
        loop {
            let next = Arc::new(f(&current));
            let next_ptr = Arc::as_ptr(&next).cast_mut();
            match self.current.compare_exchange(
                current.ptr.cast_mut(),
                next_ptr,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(prev) => {
                    // The cell now owns `next`'s strong count.
                    let published = Arc::into_raw(next);
                    debug_assert!(std::ptr::eq(published, next_ptr));
                    let EpochGuard { pin, .. } = current;
                    self.retire(prev, pin);
                    return;
                }
                // Another write won. `next` was never published and drops
                // here. `actual` was loaded under the same, still-held pin, so
                // the guard covers it exactly as it covered the first load.
                Err(actual) => current.ptr = actual.cast_const(),
            }
        }
    }

    /// Takes ownership of `prev`, the pointer a write just exchanged out of the
    /// cell, and releases it once no reader can still hold it.
    ///
    /// `pin` must be the guard the write held across the exchange.
    fn retire(&self, prev: *mut T, pin: epoch::Guard) {
        // SAFETY: `prev` is the pointer this cell held until the swap or
        // compare-and-swap that returned it: produced by `Arc::into_raw`, with
        // one strong count owned by the cell. The atomic exchange removed it
        // from the cell, so exactly one write receives it and adopts that
        // count here; nothing else ever will.
        let value = unsafe { Arc::from_raw(prev) };

        let grace_elapsed = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&grace_elapsed);
        // Registered after the exchange, while still pinned in `COLLECTOR`: it
        // runs only once every thread pinned there now — every reader that
        // could have loaded `prev`, since a load pins `COLLECTOR` too — has
        // unpinned. It raises a flag instead of dropping `value` because it
        // may run inside any thread's `pin()`, readers included.
        pin.defer(move || signal.store(true, Ordering::Release));
        // Seal the callback into the collector's queue now, so its grace
        // period is counted from this write rather than from whenever this
        // thread's local bag next fills.
        pin.flush();
        drop(pin);

        self.retired
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Retired {
                _value: value,
                grace_elapsed: Arc::clone(&grace_elapsed),
            });

        nudge_collector(&grace_elapsed);
        self.release_elapsed();
    }

    /// Releases every retired value whose grace period has ended, after
    /// nudging the epoch collector towards ending the newest one.
    ///
    /// Every write already does this for the value it replaced, but a grace
    /// period can outlast the write — a reader preempted while pinned holds the
    /// epoch back — and the value then waits for the next write to this cell.
    /// Call this after the last write of a burst to a cell that is rarely
    /// written, such as a memtable after a flush, so a large replaced value is
    /// not held until the next burst.
    pub fn reclaim(&self) {
        let newest = self
            .retired
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last()
            .map(|retired| Arc::clone(&retired.grace_elapsed));
        if let Some(grace_elapsed) = newest {
            nudge_collector(&grace_elapsed);
        }
        self.release_elapsed();
    }

    /// How many replaced values the cell is still holding, released or not.
    /// Lets a consumer's tests prove a write path does not keep a large value
    /// alive after it returns.
    #[cfg(test)]
    pub(crate) fn retired_len(&self) -> usize {
        self.retired
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Drops every retired value whose grace period has ended.
    ///
    /// The destructors run on this (writing) thread, after the lock is
    /// released, so a large value never runs its destructor under the lock.
    fn release_elapsed(&self) {
        let released: Vec<Retired<T>> = self
            .retired
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extract_if(.., |retired| retired.grace_elapsed())
            .collect();
        drop(released);
    }
}

/// Drives the epoch collector until `grace_elapsed` is raised, at most
/// [`RECLAIM_NUDGES`] times.
fn nudge_collector(grace_elapsed: &AtomicBool) {
    for _ in 0..RECLAIM_NUDGES {
        if grace_elapsed.load(Ordering::Acquire) {
            return;
        }
        // A guard further up this thread's stack holds the collector's epoch
        // back, so no nudge can end the grace period until it drops. A later
        // write releases the value instead.
        if is_pinned() {
            return;
        }
        pin().flush();
    }
}

impl<T> Drop for EpochCell<T> {
    fn drop(&mut self) {
        let current = *self.current.get_mut();
        // SAFETY: `current` came from `Arc::into_raw` and the cell owns one
        // strong count for it. `&mut self` proves no `EpochGuard` and no
        // in-flight `load_full` borrows this cell, so nothing reads through
        // `current` again; adopting the count releases the cell's share.
        drop(unsafe { Arc::from_raw(current) });
        // `retired` drops with the cell. Their grace periods need not have
        // ended: a reader can only reach a retired value through a borrow of
        // this cell, and `&mut self` proves there is none.
    }
}

impl<T: Default> Default for EpochCell<T> {
    fn default() -> Self {
        Self::from_pointee(T::default())
    }
}

impl<T: fmt::Debug> fmt::Debug for EpochCell<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EpochCell").field(&*self.load()).finish()
    }
}

/// The `Option<Arc<T>>` form of [`EpochCell`], the replacement for
/// `ArcSwapOption`.
///
/// A safe wrapper over `EpochCell<Option<Arc<T>>>` that adds no `unsafe` of
/// its own. A store allocates the small `Option` box that loads dereference
/// through; a load costs what [`EpochCell::load`] costs.
pub struct EpochCellOption<T> {
    inner: EpochCell<Option<Arc<T>>>,
}

impl<T> EpochCellOption<T> {
    /// Creates an empty cell.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            inner: EpochCell::from_pointee(None),
        }
    }

    /// Returns a pinned view of the current value. The same rules as
    /// [`EpochCell::load`] apply: drop the guard promptly.
    #[inline]
    pub fn load(&self) -> EpochGuard<'_, Option<Arc<T>>> {
        self.inner.load()
    }

    /// Returns the current value as an owned `Arc`, if any: a load, plus one
    /// atomic refcount increment when a value is present.
    #[must_use]
    pub fn load_full(&self) -> Option<Arc<T>> {
        self.inner.load().as_ref().map(Arc::clone)
    }

    /// Replaces the current value with `value`.
    pub fn store(&self, value: Option<Arc<T>>) {
        self.inner.store(Arc::new(value));
    }

    /// Releases retired values whose grace period has ended; see
    /// [`EpochCell::reclaim`].
    pub fn reclaim(&self) {
        self.inner.reclaim();
    }

    /// See [`EpochCell::retired_len`].
    #[cfg(test)]
    pub(crate) fn retired_len(&self) -> usize {
        self.inner.retired_len()
    }
}

impl<T> Default for EpochCellOption<T> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<T: fmt::Debug> fmt::Debug for EpochCellOption<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EpochCellOption")
            .field(&*self.inner.load())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{EpochCell, EpochCellOption};
    use proptest::prelude::*;
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;

    /// Scales a stress test's iteration count down under Miri, which
    /// interprets every memory access: there the point is checking the
    /// `unsafe` blocks against the interleavings Miri schedules, not volume.
    /// `make miri` runs these tests that way, from `unsafe-check/` (CI: the
    /// `unsafe-code` job), with `-Zmiri-tree-borrows -Zmiri-ignore-leaks` —
    /// `crossbeam-epoch`'s intrusive list trips Stacked Borrows inside the
    /// crate, and the cells' collector, a static, never frees its own bags at
    /// exit.
    const fn stress(n: u64) -> u64 {
        if cfg!(miri) {
            n / 100 + 2
        } else {
            n
        }
    }

    /// A value that counts its own construction and destruction, so a test can
    /// prove exactly when the cell released it — and that it released each
    /// value once.
    struct Tracked {
        id: u64,
        drops: Arc<AtomicUsize>,
    }

    impl Tracked {
        fn new(id: u64, drops: &Arc<AtomicUsize>) -> Self {
            Self {
                id,
                drops: Arc::clone(drops),
            }
        }
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn load_and_load_full_see_the_initial_value() {
        let cell = EpochCell::from_pointee(7_u64);
        assert_eq!(*cell.load(), 7);

        let full = cell.load_full();
        assert_eq!(*full, 7);
        let guard = cell.load();
        assert!(
            std::ptr::eq(std::ptr::from_ref::<u64>(&guard), Arc::as_ptr(&full)),
            "load and load_full must reach the same allocation"
        );
    }

    #[test]
    fn from_arc_adopts_the_shared_value() {
        let shared = Arc::new(String::from("initial"));
        let cell = EpochCell::from_arc(Arc::clone(&shared));
        assert!(Arc::ptr_eq(&cell.load_full(), &shared));

        let next = Arc::new(String::from("replaced"));
        cell.store(Arc::clone(&next));
        assert!(Arc::ptr_eq(&cell.load_full(), &next));
        assert_eq!(*shared, "initial", "the caller's own Arc is untouched");
    }

    #[test]
    fn store_publishes_the_new_value_and_keeps_an_owned_old_one() {
        let cell = EpochCell::from_pointee(String::from("a"));
        let old = cell.load_full();

        cell.store(Arc::new(String::from("b")));

        assert_eq!(*cell.load(), "b");
        assert_eq!(*old, "a", "an Arc taken before the store outlives it");
    }

    #[test]
    fn rcu_derives_the_next_value_from_the_current_one() {
        let cell = EpochCell::from_pointee(vec![1_u32]);
        cell.rcu(|current| {
            let mut next = current.clone();
            next.push(2);
            next
        });
        assert_eq!(*cell.load(), vec![1, 2]);
    }

    /// The claims cache depends on this: its generation check lives inside the
    /// `rcu` closure and is only sound if a write that lands between the
    /// closure's read and its publish forces the closure to run again against
    /// the value that write installed.
    #[test]
    fn rcu_reruns_against_the_value_a_racing_writer_installed() {
        let cell = EpochCell::from_pointee(0_u64);
        let mut seen = Vec::new();

        cell.rcu(|current| {
            seen.push(*current);
            if seen.len() == 1 {
                // A writer lands between this closure's read and its publish.
                cell.store(Arc::new(100));
            }
            *current + 1
        });

        assert_eq!(
            seen,
            vec![0, 100],
            "the closure must re-run against the racing writer's value"
        );
        assert_eq!(*cell.load(), 101, "the racing store must not be lost");
    }

    /// Drives the cell's own reclamation until `drops` reaches `expected`.
    ///
    /// The release must come from the cell — `reclaim` is its writer-side
    /// release, the one a write runs itself — but in a test process shared
    /// with other tests, a thread of theirs that is pinned at the wrong moment
    /// delays a grace period by an unpredictable amount. The strict version,
    /// released before the write returns, needs a process nothing else pins
    /// in: `tests/epoch_cell_hot_path.rs` checks it there.
    fn reclaim_until<T>(cell: &EpochCell<T>, drops: &AtomicUsize, expected: usize) {
        for _ in 0..100_000 {
            if drops.load(Ordering::SeqCst) >= expected {
                break;
            }
            cell.reclaim();
            thread::yield_now();
        }
        assert_eq!(
            drops.load(Ordering::SeqCst),
            expected,
            "the cell did not release exactly the replaced values"
        );
    }

    #[test]
    fn a_write_releases_what_it_replaced_once_no_reader_can_hold_it() {
        let drops = Arc::new(AtomicUsize::new(0));
        let cell = EpochCell::from_pointee(Tracked::new(0, &drops));

        cell.store(Arc::new(Tracked::new(1, &drops)));
        reclaim_until(&cell, &drops, 1);

        cell.rcu(|current| Tracked::new(current.id + 1, &drops));
        reclaim_until(&cell, &drops, 2);
        assert_eq!(cell.load().id, 2);
    }

    #[test]
    fn a_pinned_reader_keeps_a_replaced_value_alive() {
        let drops = Arc::new(AtomicUsize::new(0));
        let cell = Arc::new(EpochCell::from_pointee(Tracked::new(0, &drops)));
        let (pinned_tx, pinned_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();

        let reader = thread::spawn({
            let cell = Arc::clone(&cell);
            move || {
                let guard = cell.load();
                pinned_tx.send(guard.id).expect("main thread is listening");
                release_rx.recv().expect("main thread releases the reader");
                // Read through the guard AFTER two writes replaced its value.
                guard.id
            }
        });

        assert_eq!(pinned_rx.recv().expect("reader pinned"), 0);
        cell.store(Arc::new(Tracked::new(1, &drops)));
        cell.store(Arc::new(Tracked::new(2, &drops)));
        assert_eq!(
            drops.load(Ordering::SeqCst),
            0,
            "nothing may be released while a reader that pinned before the writes is still pinned"
        );

        release_tx.send(()).expect("reader is waiting");
        assert_eq!(
            reader.join().expect("reader thread"),
            0,
            "the pinned reader still reads the value it loaded"
        );

        // The reader has unpinned, so the next write can release all three.
        cell.store(Arc::new(Tracked::new(3, &drops)));
        reclaim_until(&cell, &drops, 3);
        assert_eq!(cell.load().id, 3);
    }

    thread_local! {
        static IS_READER: Cell<bool> = const { Cell::new(false) };
    }

    /// Counts drops that ran on a thread marked as a reader.
    struct DropSite {
        on_reader: Arc<AtomicUsize>,
    }

    impl Drop for DropSite {
        fn drop(&mut self) {
            if IS_READER.with(Cell::get) {
                self.on_reader.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    /// `crossbeam-epoch` runs deferred work inside whichever thread's `pin()`
    /// happens to collect it — on the hot path that is usually a reader. A
    /// replaced value can be a whole cache map, so the cell must never let its
    /// destructor run there: readers only load, and the cost of freeing what a
    /// write replaced stays on the write path.
    #[test]
    fn replaced_values_are_never_dropped_on_a_reader_thread() {
        let on_reader = Arc::new(AtomicUsize::new(0));
        let cell = Arc::new(EpochCell::from_pointee(DropSite {
            on_reader: Arc::clone(&on_reader),
        }));
        let stop = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..4)
            .map(|_| {
                let cell = Arc::clone(&cell);
                let stop = Arc::clone(&stop);
                thread::spawn(move || {
                    IS_READER.with(|r| r.set(true));
                    let mut loads = 0_u64;
                    while !stop.load(Ordering::Relaxed) || loads < stress(1_000) {
                        let guard = cell.load();
                        std::hint::black_box(&*guard);
                        loads += 1;
                    }
                })
            })
            .collect();

        for _ in 0..stress(2_000) {
            cell.store(Arc::new(DropSite {
                on_reader: Arc::clone(&on_reader),
            }));
        }
        stop.store(true, Ordering::Relaxed);
        for r in readers {
            r.join().expect("reader thread");
        }

        assert_eq!(
            on_reader.load(Ordering::SeqCst),
            0,
            "a replaced value was dropped inside a reader"
        );
    }

    /// Work that other code defers to `crossbeam-epoch`'s default collector —
    /// `crossbeam-skiplist` frees memtable nodes there — must never run inside
    /// an `EpochCell` load. A load's pin runs a slice of its collector's
    /// pending work every 128 pins, so on a shared collector a
    /// `validate_token` read would run another subsystem's destructors.
    #[test]
    fn loads_never_run_work_deferred_to_the_default_collector() {
        static RAN_ON_READER: AtomicUsize = AtomicUsize::new(0);
        fn note_if_on_reader() {
            // `try_with`: a deferred function can run while some thread's
            // thread-locals are being torn down.
            if IS_READER.try_with(Cell::get).unwrap_or(false) {
                RAN_ON_READER.fetch_add(1, Ordering::SeqCst);
            }
        }

        let cell = Arc::new(EpochCell::from_pointee(0_u64));
        let stop = Arc::new(AtomicBool::new(false));
        let start = Arc::new(Barrier::new(5));

        let readers: Vec<_> = (0..4)
            .map(|_| {
                let cell = Arc::clone(&cell);
                let stop = Arc::clone(&stop);
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    IS_READER.with(|r| r.set(true));
                    start.wait();
                    let mut loads = 0_u64;
                    while !stop.load(Ordering::Relaxed) || loads < stress(100_000) {
                        std::hint::black_box(*cell.load());
                        loads += 1;
                    }
                })
            })
            .collect();

        start.wait();
        for _ in 0..stress(20_000) {
            let guard = crossbeam_epoch::pin();
            guard.defer(note_if_on_reader);
            guard.flush();
        }
        stop.store(true, Ordering::Relaxed);
        for r in readers {
            r.join().expect("reader thread");
        }

        assert_eq!(
            RAN_ON_READER.load(Ordering::SeqCst),
            0,
            "an EpochCell load ran work deferred to crossbeam-epoch's default collector"
        );
    }

    /// The other half of having a collector of its own: a guard held on
    /// `crossbeam-epoch`'s default collector (a `crossbeam-skiplist` read, say)
    /// cannot hold back the grace period of a value an `EpochCell` replaced.
    #[test]
    fn a_default_collector_guard_does_not_hold_back_reclamation() {
        let drops = Arc::new(AtomicUsize::new(0));
        let cell = EpochCell::from_pointee(Tracked::new(0, &drops));

        let foreign = crossbeam_epoch::pin();
        cell.store(Arc::new(Tracked::new(1, &drops)));
        reclaim_until(&cell, &drops, 1);
        drop(foreign);

        assert_eq!(cell.load().id, 1);
    }

    /// Writers racing on `rcu` must not lose an increment, and concurrent
    /// readers must never observe a value that went backwards.
    #[test]
    fn concurrent_rcu_never_loses_an_update() {
        const WRITERS: u64 = 4;
        const PER_WRITER: u64 = stress(2_500);

        let cell = Arc::new(EpochCell::from_pointee(0_u64));
        let stop = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..4)
            .map(|_| {
                let cell = Arc::clone(&cell);
                let stop = Arc::clone(&stop);
                thread::spawn(move || {
                    let mut last = 0_u64;
                    while !stop.load(Ordering::Relaxed) {
                        let seen = *cell.load();
                        assert!(seen >= last, "counter went backwards: {last} then {seen}");
                        assert!(seen <= WRITERS * PER_WRITER, "counter overshot: {seen}");
                        last = seen;
                    }
                })
            })
            .collect();

        let writers: Vec<_> = (0..WRITERS)
            .map(|_| {
                let cell = Arc::clone(&cell);
                thread::spawn(move || {
                    for _ in 0..PER_WRITER {
                        cell.rcu(|current| *current + 1);
                    }
                })
            })
            .collect();

        for w in writers {
            w.join().expect("writer thread");
        }
        stop.store(true, Ordering::Relaxed);
        for r in readers {
            r.join().expect("reader thread");
        }

        assert_eq!(
            *cell.load(),
            WRITERS * PER_WRITER,
            "an rcu increment was lost"
        );
    }

    /// `store` must publish every value it is handed, with the last store
    /// winning, while readers are loading concurrently.
    #[test]
    fn concurrent_store_publishes_the_last_value() {
        const STORES: u64 = stress(5_000);

        let cell = Arc::new(EpochCell::from_pointee(0_u64));
        let stop = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..4)
            .map(|_| {
                let cell = Arc::clone(&cell);
                let stop = Arc::clone(&stop);
                thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let seen = *cell.load_full();
                        assert!(seen <= STORES, "observed a value never stored: {seen}");
                    }
                })
            })
            .collect();

        for i in 1..=STORES {
            cell.store(Arc::new(i));
        }
        stop.store(true, Ordering::Relaxed);
        for r in readers {
            r.join().expect("reader thread");
        }

        assert_eq!(*cell.load(), STORES, "the last store was not published");
    }

    /// A value whose parts must agree. A reader that ever sees them disagree
    /// saw a torn or freed value.
    #[derive(Clone)]
    struct Versioned {
        version: u64,
        check: u64,
        label: String,
        payload: HashMap<u64, Vec<String>>,
    }

    impl Versioned {
        fn new(version: u64) -> Self {
            let payload = (0..=(version % 8))
                .map(|k| (k, vec![version.to_string(); 3]))
                .collect();
            Self {
                version,
                check: !version,
                label: format!("v{version}"),
                payload,
            }
        }

        fn assert_consistent(&self) {
            assert_eq!(self.check, !self.version, "torn header");
            assert_eq!(self.label, format!("v{}", self.version), "torn label");
            assert_eq!(
                self.payload.len() as u64,
                (self.version % 8) + 1,
                "torn map"
            );
            let expected = self.version.to_string();
            for strings in self.payload.values() {
                assert!(strings.iter().all(|s| *s == expected), "torn payload");
            }
        }
    }

    /// The shape of the `arc-swap` fault (task 26.1): readers walking heap-owned
    /// data inside a snapshot while writers replace it. Run several copies at
    /// once with glibc's heap checking on — `MALLOC_CHECK_=3` with
    /// `libc_malloc_debug.so` preloaded (glibc 2.34+ ignores the variable
    /// without it) and `MALLOC_PERTURB_=165` — so a use-after-free aborts or
    /// reads garbage rather than intact stale memory; see
    /// `https://github.com/hearth-auth/hearth/blob/4d9dda1f5b514891e90dadeffb03d1a026af4e51/reports/arc-swap-use-after-free-2026-09-21.md`. `make heap-check` does
    /// exactly that (CI: the `quality` job), and `make asan` runs it under
    /// AddressSanitizer.
    #[test]
    fn concurrent_readers_never_observe_a_torn_or_freed_value() {
        const WRITERS: u64 = 2;
        const PER_WRITER: u64 = stress(1_500);

        let cell = Arc::new(EpochCell::from_pointee(Versioned::new(0)));
        let stop = Arc::new(AtomicBool::new(false));
        let start = Arc::new(Barrier::new(4 + WRITERS as usize));

        let readers: Vec<_> = (0..4)
            .map(|i| {
                let cell = Arc::clone(&cell);
                let stop = Arc::clone(&stop);
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    let mut last = 0_u64;
                    while !stop.load(Ordering::Relaxed) {
                        let version = if i % 2 == 0 {
                            let guard = cell.load();
                            guard.assert_consistent();
                            guard.version
                        } else {
                            let owned = cell.load_full();
                            owned.assert_consistent();
                            owned.version
                        };
                        assert!(version >= last, "version went backwards");
                        last = version;
                    }
                })
            })
            .collect();

        let writers: Vec<_> = (0..WRITERS)
            .map(|_| {
                let cell = Arc::clone(&cell);
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    for _ in 0..PER_WRITER {
                        // The closure reads the value it replaces, so a writer
                        // is also a reader of a value another writer may be
                        // retiring at that moment.
                        cell.rcu(|current| {
                            current.assert_consistent();
                            Versioned::new(current.version + 1)
                        });
                    }
                })
            })
            .collect();

        for w in writers {
            w.join().expect("writer thread");
        }
        stop.store(true, Ordering::Relaxed);
        for r in readers {
            r.join().expect("reader thread");
        }

        let last = cell.load();
        last.assert_consistent();
        assert_eq!(last.version, WRITERS * PER_WRITER, "an rcu was lost");
    }

    #[test]
    fn load_full_outlives_the_cell() {
        let cell = EpochCell::from_pointee(String::from("kept"));
        let owned = cell.load_full();
        drop(cell);
        assert_eq!(*owned, "kept");
    }

    #[test]
    fn dropping_the_cell_releases_every_value_it_still_holds() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let cell = EpochCell::from_pointee(Tracked::new(0, &drops));
            // Keep this thread pinned in the cells' collector so no write can
            // release anything: every replaced value is still on the retired
            // list when the cell drops.
            let pin = super::pin();
            for id in 1..=5 {
                cell.store(Arc::new(Tracked::new(id, &drops)));
            }
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            drop(pin);
        }
        assert_eq!(
            drops.load(Ordering::SeqCst),
            6,
            "the current value and all five retired ones, each exactly once"
        );
    }

    #[test]
    fn option_cell_round_trips_some_and_none() {
        let cell: EpochCellOption<String> = EpochCellOption::empty();
        assert!(cell.load().is_none());
        assert!(cell.load_full().is_none());

        cell.store(Some(Arc::new(String::from("parked"))));
        assert_eq!(cell.load().as_deref().map(String::as_str), Some("parked"));
        let owned = cell.load_full().expect("a value is stored");

        cell.store(None);
        assert!(cell.load().is_none());
        assert_eq!(*owned, "parked", "an owned Arc outlives the clear");
    }

    #[derive(Debug, Clone)]
    enum Op {
        Store(u64),
        Add(u64),
        HoldThenStore(u64),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            any::<u64>().prop_map(Op::Store),
            any::<u64>().prop_map(Op::Add),
            any::<u64>().prop_map(Op::HoldThenStore),
        ]
    }

    /// The default configuration (so `PROPTEST_CASES` still applies), except
    /// under Miri: a handful of cases, and no failure file, which Miri's
    /// isolation would refuse to write.
    fn proptest_config() -> ProptestConfig {
        if cfg!(miri) {
            ProptestConfig {
                cases: 4,
                failure_persistence: None,
                ..ProptestConfig::default()
            }
        } else {
            ProptestConfig::default()
        }
    }

    proptest! {
        #![proptest_config(proptest_config())]

        /// Any sequence of writes leaves the cell equal to a plain model, and
        /// every value the cell was ever handed is released exactly once.
        #[test]
        fn any_write_sequence_matches_a_model_and_releases_each_value_once(
            ops in proptest::collection::vec(op(), 0..48)
        ) {
            let drops = Arc::new(AtomicUsize::new(0));
            let mut created = 1_usize;
            let cell = EpochCell::from_pointee(Tracked::new(0, &drops));
            let mut model = 0_u64;

            for op in ops {
                match op {
                    Op::Store(v) => {
                        cell.store(Arc::new(Tracked::new(v, &drops)));
                        model = v;
                    }
                    Op::Add(d) => {
                        cell.rcu(|current| Tracked::new(current.id.wrapping_add(d), &drops));
                        model = model.wrapping_add(d);
                    }
                    Op::HoldThenStore(v) => {
                        let held = cell.load_full();
                        cell.store(Arc::new(Tracked::new(v, &drops)));
                        prop_assert_eq!(held.id, model, "a held Arc kept its value");
                        model = v;
                    }
                }
                created += 1;
                prop_assert_eq!(cell.load().id, model);
                prop_assert_eq!(cell.load_full().id, model);
            }

            drop(cell);
            prop_assert_eq!(drops.load(Ordering::SeqCst), created);
        }
    }
}
