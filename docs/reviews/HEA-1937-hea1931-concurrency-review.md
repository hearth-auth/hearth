# HEA-1937 — Concurrency review of HEA-1931 (`5570b721`)

**Verdict: CHANGES REQUESTED.** One HIGH-severity correctness regression in `compact_ssts`.
Claims 1, 2 and 4 verified sound; claim 3 is **half true** — the delete-set reasoning is
correct, the recency-ordering reasoning is not.

---

## F1 (HIGH) — `compact_ssts` output can be numbered *above* a concurrently flushed SST, inverting recency

`src/storage/engine.rs:770-806`

`compact_ssts` snapshots the reader list and then allocates its output number from
`sst_counter` — **both with no lock that excludes an in-flight flush**:

```rust
let sst_readers = self.sst_readers.load();          // :775  no flush_lock
let old_sst_nums = ...;                             // :786
let sst_num = self.sst_counter.fetch_add(1, ...);   // :802  no flush_lock
```

`trigger_flush` (`:569`) holds `flush_lock` across its *whole* body — including its own
`sst_counter.fetch_add` (`:578`), the SST write (`:600`), and only then the
`sst_readers.store` (`:616`). Same shape in the WAL pre-rotate callback (`:458-535`).

Before this commit `compact_ssts` took `flush_lock` first, so snapshot and number
allocation were ordered against every flush. HEA-1931 removed that lock and left the
allocation where it was. The window is now the entire duration of a flush's SST
encrypt+fsync.

### Failing interleaving

| t | flush (holds `flush_lock`) | `compact_ssts` (holds only `compaction_lock`) |
|---|---|---|
| t0 | `fetch_add` → **6**; begins writing `000006.sst` | |
| t1 | (still writing) | `load()` → `[5,4,3]` (6 not published yet) |
| t2 | (still writing) | `fetch_add` → **7**; merges `{5,4,3}` → `000007.sst.tmp` |
| t3 | `reload` → stores `[6,5,4,3]`; releases lock | |
| t4 | | takes `flush_lock`, renames → `000007.sst`, deletes 5/4/3, `reload` → **`[7, 6]`** |

SST 7 is the merge of `{5,4,3}` — strictly **older** data than SST 6. Newest-first
resolution puts 7 ahead of 6, so **6's values are permanently shadowed by 5's**.

Concretely: user changes password. Old Argon2id hash lives in SST 5, new hash is flushed
into SST 6. After the hourly sweep, `get()` returns the **old hash** — the old password
works again and the new one does not. A delete tombstone in 6 is likewise shadowed →
**deleted user resurrects**. This is not transient: recovery (`open_with_fs`) sorts by
number descending too, so the inversion survives restart, and if the WAL rotated the
correct value is gone entirely.

Reachable in production: `src/main.rs:1770` runs `compact_ssts` on the hourly ticker in
`spawn_blocking`, concurrent with live writes.

`compact_partial` is **not** affected — it reuses `target_num` (`:937`, `:962`), the run's
max input number, which is by construction below any concurrently flushed file. That is
exactly the invariant `compact_ssts` lost.

### Recommended fix (minimal)

Take `flush_lock` for the snapshot + `fetch_add`, release it before the merge:

```rust
let (sst_readers, sst_num) = {
    let _g = self.flush_lock.lock().map_err(...)?;
    let readers = self.sst_readers.load_full();
    if readers.len() < min_sst_count { return Ok(0); }
    (readers, self.sst_counter.fetch_add(1, Ordering::Relaxed))
};
```

No flush can be mid-allocation while that lock is held, so every subsequent flush is
numbered above `sst_num`. Lock order stays `compaction_lock → flush_lock`. The merge and
the existing commit-phase reload are unchanged.

*Do not* renumber at commit time instead: `sst_num` is baked into the v3 per-block nonces
and AAD by `compact_with_fs`, so the output cannot be renamed to a different number.

Alternative (matches `compact_partial`): reuse `max(old_sst_nums)` as the output number —
but then the delete loop at `:842` must skip `target_num`, or it unlinks the file just
renamed into place.

---

## F2 (LOW) — the new test pins `compact_partial` only; the regressed path is untested

`compaction_merge_io_does_not_hold_flush_lock` (`:2627`) is a genuine RED→GREEN pin — it
parks the merge inside a gated `Fs::create` and `try_lock`s `flush_lock` from another
thread. But it exercises `compact_partial`. There is no test running `compact_ssts`
concurrently with a flush, which is why F1 shipped green across 323 tests.

Add a regression test alongside the F1 fix: gate the flush's SST `create`, start
`compact_ssts` while it is parked, release, and assert the post-compaction `get()` returns
the value written into the concurrently flushed SST.

---

## Verified sound

1. **Lock order** — `compaction_lock` is taken before `flush_lock` in both `compact_ssts`
   (`:768` → `:825`) and `compact_partial` (`:915` → `:981`). Nothing acquires them in the
   other order; `trigger_flush` and the WAL callback take `flush_lock` alone and never call
   into compaction (`:622` only does `notify_one`, a flag set — the merge runs on the
   background task at `main.rs:1774`). **No inversion, no deadlock.**
2. **Claim (b) — flushes only add** — confirmed by reading both flush paths. `trigger_flush`
   (`:600-616`) and the pre-rotate callback (`:485-531`) each write exactly one new file and
   rebuild by directory scan; neither calls `remove_file` nor renames. `compaction_lock`
   excludes the only other deleter. So a pinned `Arc` snapshot's members stay on disk and
   mmap-valid for the whole merge. ✔
3. **Delete set** — `old_sst_nums`/`other_nums` are captured pre-merge, so a file flushed
   during the merge is never unlinked. ✔ (The *ordering* half of this claim is F1.)
4. **`drop_tombstones = end == len-1`** — valid. Reload sorts descending, so new files land
   at the front; the tail stays the oldest. The only thing that could remove tail entries is
   another compaction, excluded by `compaction_lock`. ✔
5. `.sst.tmp` / `.sst.partial.tmp` are filtered out of `reload_sst_readers` (`:649`, extension
   is `tmp`), so a concurrent flush's rescan never picks up an in-progress merge. ✔
6. `compaction_records_written` doc ("incremented under `flush_lock`", `:295`) still holds —
   both increments moved into the commit phase. ✔
7. Config default flip `0 → 12` is consistent across `CompactionConfig`, `CompactionSection`,
   `default_max_sst_count()`, `hearth.example.yaml`, and CHANGELOG. ✔

---

## Note on the default flip

`max_sst_count: 12` raises compaction frequency substantially, but the F1 window belongs to
`compact_ssts` (the hourly sweep), which the flip does not schedule. Still, gate the flip on
the F1 fix: both compaction paths now run off `flush_lock`, and shipping the default ON makes
any residual off-lock hazard a production default rather than an opt-in.
