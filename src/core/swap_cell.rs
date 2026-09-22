//! [`SwapCell`] — a shared read-copy-update cell, the replacement for `ArcSwap`.
//!
//! # Why this exists (task 26.1)
//!
//! `arc-swap` 1.9.2 corrupts the heap under the `load` + `rcu` pattern this
//! codebase uses. Measured on 2026-09-21 against
//! `rbac::resolution_cache::tests::concurrent_readers_never_observe_stale_after_bump`,
//! run under `MALLOC_CHECK_=3` with three copies of the test binary in flight
//! so readers and the writer actually interleave:
//!
//! | Primitive | Failures in 150 loaded runs |
//! |---|---|
//! | `arc_swap::ArcSwap` 1.9.2 | **3** — two `SIGSEGV`, one `free(): invalid size` |
//! | [`SwapCell`] | 0 |
//!
//! The captured abort ran a map's destructor from a *reader's* guard drop while
//! the writer still owned it. The call sites involved contain no `unsafe`, so
//! the fault cannot originate in them. There is no release to upgrade to —
//! 1.9.2 is the newest (2026-06-28) and changes only a doc note over 1.9.1 —
//! and the crate's own `RwLock` strategy is gated behind
//! `internal-test-strategies`, which its module doc says is "not meant to be
//! used in production code". The remedy is therefore to move off the crate.
//!
//! # Where this may be used
//!
//! Everywhere *except* the hot path. `CLAUDE.md` forbids locks on the read path
//! of `validate_token`, `lookup_session` and `lookup_user`; those sites need
//! epoch-based reclamation instead and are enumerated in
//! `reports/arc-swap-use-after-free-2026-09-21.md`.
//!
//! # Why this type lives in `core`
//!
//! `core` is the one module every layer may depend on, and the consumers span
//! `protocol`, `rbac`, `abuse` and the binary; `SwapCell` is a shared generic
//! container carrying no domain logic and no I/O, in the same family as the
//! primitives already in [`crate::core::secrets`] and the atomic-backed
//! `FakeClock` in this layer.

use std::sync::{Arc, PoisonError, RwLock};

/// A cell holding an `Arc<T>` that readers clone and writers replace wholesale.
///
/// The read-copy-update shape `ArcSwap` provides, without `ArcSwap`. See the
/// module docs for why (task 26.1).
///
/// A reader takes the read lock only long enough to bump a refcount, so readers
/// never block readers and never hold the lock across any work. A writer builds
/// the next value *before* taking the write lock in [`rcu`](Self::rcu), so the
/// exclusive window is one pointer store.
///
/// A poisoned lock is recovered rather than propagated throughout: every
/// current consumer holds a value that is either re-derivable from storage or
/// re-readable from disk, so refusing to read would turn an unrelated panic
/// into a permanent outage of whatever the cell guards.
#[derive(Debug)]
pub struct SwapCell<T> {
    inner: RwLock<Arc<T>>,
}

impl<T> SwapCell<T> {
    /// Creates a cell owning `value`.
    #[must_use]
    pub fn from_pointee(value: T) -> Self {
        Self::from_arc(Arc::new(value))
    }

    /// Creates a cell from an already-shared `value`.
    #[must_use]
    pub fn from_arc(value: Arc<T>) -> Self {
        Self {
            inner: RwLock::new(value),
        }
    }

    /// Returns the current value.
    #[must_use]
    pub fn load(&self) -> Arc<T> {
        Arc::clone(&self.inner.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Replaces the current value with `value`.
    ///
    /// Readers already holding the previous `Arc` keep it alive and finish
    /// against it; readers arriving after the store observe `value`.
    pub fn store(&self, value: Arc<T>) {
        *self.inner.write().unwrap_or_else(PoisonError::into_inner) = value;
    }

    /// Replaces the value with `f(current)`.
    ///
    /// Unlike `ArcSwap::rcu` this is not a compare-and-swap retry loop: the
    /// write lock makes the read-modify-write atomic outright, so `f` runs
    /// exactly once and no update can be lost.
    pub fn rcu<F>(&self, f: F)
    where
        F: FnOnce(&Arc<T>) -> T,
    {
        let mut guard = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        let next = Arc::new(f(&guard));
        *guard = next;
    }
}

#[cfg(test)]
mod tests {
    use super::SwapCell;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// Writers racing on `rcu` must not lose an increment, and concurrent
    /// readers must never observe a value that went backwards.
    ///
    /// This is the generic guard for every `SwapCell` consumer that mutates
    /// through `rcu`. A compare-and-swap implementation that dropped a retry,
    /// or a `rcu` that computed the next value but failed to publish it, loses
    /// updates and fails the final equality.
    #[test]
    fn concurrent_rcu_never_loses_an_update() {
        const WRITERS: u64 = 4;
        const PER_WRITER: u64 = 250;

        let cell = Arc::new(SwapCell::from_pointee(0_u64));
        let stop = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..4)
            .map(|_| {
                let cell = Arc::clone(&cell);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
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
                std::thread::spawn(move || {
                    for _ in 0..PER_WRITER {
                        cell.rcu(|current| **current + 1);
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
        const STORES: u64 = 2_000;

        let cell = Arc::new(SwapCell::from_pointee(0_u64));
        let stop = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..4)
            .map(|_| {
                let cell = Arc::clone(&cell);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut observed_nonzero = false;
                    while !stop.load(Ordering::Relaxed) {
                        let seen = *cell.load();
                        assert!(seen <= STORES, "observed a value never stored: {seen}");
                        observed_nonzero |= seen > 0;
                    }
                    observed_nonzero
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

    #[test]
    fn from_arc_adopts_the_shared_value() {
        let shared = Arc::new(String::from("initial"));
        let cell = SwapCell::from_arc(Arc::clone(&shared));
        assert!(Arc::ptr_eq(&cell.load(), &shared));

        let next = Arc::new(String::from("replaced"));
        cell.store(Arc::clone(&next));
        assert!(Arc::ptr_eq(&cell.load(), &next));
    }
}
