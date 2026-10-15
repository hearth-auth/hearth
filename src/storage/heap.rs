//! Gives the heap memory that glibc keeps after a large free back to the
//! system (#445).
//!
//! glibc keeps the memory a program frees in its arenas, and returns it to the
//! system only from the top of an arena: memory freed below a chunk still in
//! use stays resident. A memtable flush frees the whole old memtable (64 MiB of
//! entries by default) and a compaction frees the readers of every SST it
//! merged. In a 60-minute soak on a 2-vCPU host with every cache full, the heap
//! in use stayed near 300 MB while the arenas' free memory grew from 165 MB to
//! 336 MB: the whole RSS trend. `malloc_trim(0)` gives the free pages of every
//! arena back with `madvise(MADV_DONTNEED)`.
//!
//! The `hearth` binary allocates through jemalloc, which returns freed pages
//! by itself, so there the trim covers only glibc's share: the C libraries,
//! such as zstd. A program that links this library with the system allocator,
//! such as the test suites, still gets the whole effect.

/// Gives the heap memory the allocator keeps but does not use back to the
/// system. Call it after an operation that frees a large amount of memory, off
/// the hot path: glibc locks each arena while it trims it. A no-op where the
/// allocator is not glibc's.
pub(crate) fn release_free_heap() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        let start = std::time::Instant::now();
        // SAFETY: `malloc_trim` takes no pointers; glibc locks each arena while
        // it trims it, so it is safe to call while other threads allocate.
        let released = unsafe { libc::malloc_trim(0) } == 1;
        tracing::debug!(
            released,
            elapsed_us = start.elapsed().as_micros(),
            "returned free heap memory to the system"
        );
    }
}
